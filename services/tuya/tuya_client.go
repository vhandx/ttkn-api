package tuya

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TuyaData đại diện cho dữ liệu nhiệt độ, độ ẩm
type TuyaData struct {
	Temperature float64 `json:"temperature"`
	Humidity    float64 `json:"humidity"`
}

// DeviceCache quản lý vùng nhớ đệm an toàn cho đa luồng
type DeviceCache struct {
	mu   sync.RWMutex
	data TuyaData
}

// Set cập nhật dữ liệu mới vào cache (Write Lock)
func (c *DeviceCache) Set(newData TuyaData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = newData
}

// Get lấy dữ liệu hiện tại từ cache (Read Lock)
func (c *DeviceCache) Get() TuyaData {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data
}

type TuyaClient struct {
	BaseURL      string
	ClientID     string
	ClientSecret string
	DeviceID     string
	httpClient   *http.Client

	// Quản lý Token nội bộ để tránh gọi lấy token liên tục
	mu          sync.Mutex
	accessToken string
	expireTime  time.Time
}

// Cấu trúc phản hồi Token từ Tuya
type TokenResponse struct {
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Result  struct {
		AccessToken string `json:"access_token"`
		ExpireTime  int    `json:"expire_time"` // tính bằng giây
	} `json:"result"`
}

// Cấu trúc phản hồi thông tin thiết bị từ Tuya
type DeviceStatusResponse struct {
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Result  []struct {
		Code  string      `json:"code"` // "va_temperature" hoặc "va_humidity" tùy thiết bị
		Value interface{} `json:"value"`
	} `json:"result"`
}

func NewTuyaClient(baseURL, clientID, clientSecret, deviceID string) *TuyaClient {
	return &TuyaClient{
		BaseURL:      strings.TrimSuffix(baseURL, "/"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		DeviceID:     deviceID,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

// HmacSHA256 tính toán mã băm HMAC-SHA256 và chuyển sang Hex viết hoa
func (c *TuyaClient) hmacSHA256(message string) string {
	h := hmac.New(sha256.New, []byte(c.ClientSecret))
	h.Write([]byte(message))
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// SHA256 tính hash của chuỗi (thường dùng cho empty body)
func sha256Hash(message string) string {
	h := sha256.New()
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// buildSign tính chữ ký theo chuẩn Tuya IoT
func (c *TuyaClient) buildSign(method, path, token, timestamp string) string {
	// 1. Tạo chuỗi SHA256 của Request Body (Ở đây GET API nên body rỗng "")
	contentHash := sha256Hash("")

	// 2. Tạo chuỗi StringToSign theo format của Tuya
	// Tuya yêu cầu danh sách Header tham gia ký, mặc định chúng ta để trống kết thúc bằng \n
	stringToSign := fmt.Sprintf("%s\n%s\n\n\n%s", method, path, contentHash)

	// 3. Ghép nối tổng thể: ClientID + Token (nếu có) + Timestamp + StringToSign
	message := c.ClientID + token + timestamp + stringToSign

	// 4. Ký bằng Client Secret
	return c.hmacSHA256(message)
}

func (c *TuyaClient) GetValidToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Nếu token vẫn còn hạn (trừ hao 1 phút an toàn), sử dụng lại cache
	if c.accessToken != "" && time.Now().Before(c.expireTime.Add(-1*time.Minute)) {
		return c.accessToken, nil
	}

	// Ngược lại, gọi API lấy token mới
	timestamp := fmt.Sprintf("%d", time.Now().UnixNano()/1e6)
	path := "/v1.0/token?grant_type=1"
	sign := c.buildSign("GET", path, "", timestamp)

	req, _ := http.NewRequest("GET", c.BaseURL+path, nil)
	req.Header.Set("client_id", c.ClientID)
	req.Header.Set("sign", sign)
	req.Header.Set("t", timestamp)
	req.Header.Set("sign_method", "HMAC-SHA256")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tokResp TokenResponse
	if err := json.Unmarshal(body, &tokResp); err != nil {
		return "", err
	}

	if !tokResp.Success {
		return "", fmt.Errorf("tuya auth failed: %s (code: %d)", tokResp.Msg, tokResp.Code)
	}

	// Lưu vào memory và set thời gian hết hạn
	c.accessToken = tokResp.Result.AccessToken
	c.expireTime = time.Now().Add(time.Duration(tokResp.Result.ExpireTime) * time.Second)

	return c.accessToken, nil
}

func (c *TuyaClient) FetchDeviceMetrics() (TuyaData, error) {
	var data TuyaData

	token, err := c.GetValidToken()
	if err != nil {
		return data, err
	}

	timestamp := fmt.Sprintf("%d", time.Now().UnixNano()/1e6)
	path := fmt.Sprintf("/v1.0/devices/%s/status", c.DeviceID)
	sign := c.buildSign("GET", path, token, timestamp)

	req, _ := http.NewRequest("GET", c.BaseURL+path, nil)
	req.Header.Set("client_id", c.ClientID)
	req.Header.Set("access_token", token)
	req.Header.Set("sign", sign)
	req.Header.Set("t", timestamp)
	req.Header.Set("sign_method", "HMAC-SHA256")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return data, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var statusResp DeviceStatusResponse
	if err := json.Unmarshal(body, &statusResp); err != nil {
		return data, err
	}

	if !statusResp.Success {
		return data, fmt.Errorf("failed to get status: %s", statusResp.Msg)
	}

	// Duyệt qua mảng kết quả của Tuya để bóc tách Nhiệt độ và Độ ẩm
	// Lưu ý: "temp_current", "humidity_value" là code phổ biến của Tuya, có thể thay đổi tùy dòng cảm biến của bạn.
	for _, status := range statusResp.Result {
		switch status.Code {
		case "temp_current", "va_temperature":
			if val, ok := status.Value.(float64); ok {
				data.Temperature = val
			}
		case "humidity", "va_humidity":
			if val, ok := status.Value.(float64); ok {
				data.Humidity = val
			}
		}
	}

	return data, nil
}

// worker.go (Cập nhật mới)
func StartTuyaWorker(cache *DeviceCache, client *TuyaClient) {

	// Chạy lần đầu ngay khi mở máy
	if data, err := client.FetchDeviceMetrics(); err == nil {
		cache.Set(data)
	}

	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		data, err := client.FetchDeviceMetrics()
		if err != nil {
			log.Printf("Tuya API Error: %v", err)
			continue
		}
		cache.Set(data)
		log.Printf("Cache updated from Tuya: Temp: %.1f, Humid: %.1f", data.Temperature, data.Humidity)
	}
}

func SseSensorTuyaHandler(cache *DeviceCache, w http.ResponseWriter, r *http.Request) {
	// 1. Set the mandatory headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*") // Allows cross-origin client access

	// 2. Ensure the response writer supports flushing
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	// 3. Monitor when the client disconnects
	ctx := r.Context()

	// Tần suất SSE kiểm tra và gửi dữ liệu từ Cache cho Client (Ví dụ: 2 giây/lần)
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			// Đọc dữ liệu cực nhanh từ Memory Cache (Không block API Tuya)
			currentData := cache.Get()

			// Chuyển cấu trúc dữ liệu thành JSON string
			jsonData, err := json.Marshal(currentData)
			if err != nil {
				continue
			}

			// Đẩy dữ liệu qua SSE
			fmt.Fprintf(w, "data: %s\n\n", string(jsonData))
			flusher.Flush()
		}
	}
}
