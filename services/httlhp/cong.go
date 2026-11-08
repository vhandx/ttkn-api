package httlhp

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type Cong struct {
	Id         string  `json:"id"`
	HeThong    string  `json:"heThong"`
	Ten        string  `json:"ten"`
	ToaDoX     float64 `json:"toaDoX"`
	ToaDoY     float64 `json:"toaDoY"`
	LyTrinh    string  `json:"lyTrinh"`
	TuyenDe    string  `json:"tuyenDe"`
	SoCua      int64   `json:"soCua"`
	KhauDo     string  `json:"khauDo"`
	KenhSauC   string  `json:"kenhSauC"`
	PhanLoai   string  `json:"phanLoai"`
	NhiemVu    string  `json:"nhiemVu"`
	CumQL      string  `json:"cumQL"`
	NguonTT    string  `json:"nguonTT"`
	LoaiCuaVan string  `json:"loaiCuaVan"`
	MayDongMo  string  `json:"mayDongMo"`
	DienTichPV float64 `json:"dienTichPV"`
	ChieuRongT float64 `json:"chieuRongT"`
	Dvql       string  `json:"dvql"`
	MaCT       string  `json:"maCT"`
	MaXa       string  `json:"maXa"`
	MaTinh     string  `json:"maTinh"`
}
type MapCongAdd struct {
	Layer      string  `json:"layer"`
	HeThong    string  `json:"heThong"`
	Ten        string  `json:"ten"`
	ToaDoX     float64 `json:"toaDoX"`
	ToaDoY     float64 `json:"toaDoY"`
	LyTrinh    string  `json:"lyTrinh"`
	TuyenDe    string  `json:"tuyenDe"`
	SoCua      int64   `json:"soCua"`
	KhauDo     string  `json:"khauDo"`
	KenhSauC   string  `json:"kenhSauC"`
	PhanLoai   string  `json:"phanLoai"`
	NhiemVu    string  `json:"nhiemVu"`
	CumQL      string  `json:"cumQL"`
	NguonTT    string  `json:"nguonTT"`
	LoaiCuaVan string  `json:"loaiCuaVan"`
	MayDongMo  string  `json:"mayDongMo"`
	DienTichPV float64 `json:"dienTichPV"`
	ChieuRongT float64 `json:"chieuRongT"`
	Dvql       string  `json:"dvql"`
	MaCT       string  `json:"maCT"`
	MaXa       string  `json:"maXa"`
	MaTinh     string  `json:"maTinh"`

	Geometry struct {
		Type        string    `json:"type"`
		Coordinates []float64 `json:"coordinates"`
	} `json:"geometry"`
}
type CongReport struct {
	Id         string  `json:"id"`
	HeThong    string  `json:"heThong"`
	Ten        string  `json:"ten"`
	ToaDoX     float64 `json:"toaDoX"`
	ToaDoY     float64 `json:"toaDoY"`
	LyTrinh    string  `json:"lyTrinh"`
	TuyenDe    string  `json:"tuyenDe"`
	SoCua      int64   `json:"soCua"`
	KhauDo     string  `json:"khauDo"`
	KenhSauC   string  `json:"kenhSauC"`
	PhanLoai   string  `json:"phanLoai"`
	NhiemVu    string  `json:"nhiemVu"`
	CumQL      string  `json:"cumQL"`
	NguonTT    string  `json:"nguonTT"`
	LoaiCuaVan string  `json:"loaiCuaVan"`
	MayDongMo  string  `json:"mayDongMo"`
	DienTichPV float64 `json:"dienTichPV"`
	ChieuRongT float64 `json:"chieuRongT"`
	Dvql       string  `json:"dvql"`
	MaCT       string  `json:"maCT"`
	MaXa       string  `json:"maXa"`
	MaTinh     string  `json:"maTinh"`
}

// func SaveCong(db *sql.DB, w http.ResponseWriter, body []byte) {
func SaveCong(db *sql.DB, w http.ResponseWriter, r *http.Request) {

	var data Cong

	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	aId := strings.Split(data.Id, ".")

	query := `
			UPDATE httlhp."VB_Cong"
				SET "heThong"=$1, ten=$2, 
				    "toaDoX"=$3, "toaDoY"=$4, "lyTrinh"=$5, "tuyenDe"=$6, "soCua"=$7, 
				    "khauDo"=$8, "kenhSauC"=$9, "phanLoai"=$10, "nhiemVu"=$11, "cumQL"=$12, 
				    "nguonTT"=$13, "loaiCuaVan"=$14, "mayDongMo"=$15, "dienTichPV"=$16, "chieuRongT"=$17, 
				    dvql=$18, "maCT"=$19, "maXa"=$20, "maTinh"=$21
			WHERE id = $22
		`

	_, err = db.Exec(query, data.HeThong, data.Ten,
		data.ToaDoX, data.ToaDoY, data.LyTrinh, data.TuyenDe, data.SoCua,
		data.KhauDo, data.KenhSauC, data.PhanLoai, data.NhiemVu, data.CumQL,
		data.NguonTT, data.LoaiCuaVan, data.MayDongMo, data.DienTichPV, data.ChieuRongT,
		data.Dvql, data.MaCT, data.MaXa, data.MaTinh,
		aId[1])

	if err != nil {
		log.Println("Failed to Insert:", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Update successful"})
}

func MapCong(db *sql.DB, w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data MapCongAdd
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	query := `INSERT INTO httlhp."VB_Cong"(
                             geom, "heThong", ten, "toaDoX", "toaDoY", 
                             "lyTrinh", "tuyenDe", "soCua", "khauDo", "kenhSauC", 
                             "phanLoai", "nhiemVu", "cumQL", "nguonTT", "loaiCuaVan", 
                             "mayDongMo", "dienTichPV", "chieuRongT", dvql, "maCT", 
                             "maXa", "maTinh")
			VALUES (ST_Multi(ST_SetSRID(ST_GeomFromGeoJSON($1),4326)), $2, $3, $4, $5, 
			        $6, $7, $8, $9, $10, 
			        $11, $12, $13, $14, $15, 
			        $16, $17, $18, $19, $20, 
			        $21, $22)`

	geo, err := json.Marshal(data.Geometry)
	if err != nil {
		fmt.Println("Error Marshal JSON:", err)
		return
	}

	//toaDoX, _ := strconv.ParseFloat(data.toaDoX, 64)
	//toaDoY, _ := strconv.ParseFloat(data.toaDoX, 64)
	//soCua, _ := strconv.ParseInt(data.soCua, 10, 64)
	//dienTichPV, _ := strconv.ParseFloat(data.dienTichPV, 64)
	//chieuRongT, _ := strconv.ParseFloat(data.chieuRongT, 64)

	_, err = db.Exec(query, string(geo), data.HeThong, data.Ten, data.ToaDoX, data.ToaDoY,
		data.LyTrinh, data.TuyenDe, data.SoCua, data.KhauDo, data.KenhSauC,
		data.PhanLoai, data.NhiemVu, data.CumQL, data.NguonTT, data.LoaiCuaVan,
		data.MayDongMo, data.DienTichPV, data.ChieuRongT, data.Dvql, data.MaCT,
		data.MaXa, data.MaTinh)

	if err != nil {
		log.Println("Failed to Insert:", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Insert successful"})
}

func ReportVbCong(db *sql.DB, w http.ResponseWriter, r *http.Request) {

	var sql = `SELECT id, "heThong", ten, "toaDoX", "toaDoY", 
					COALESCE("lyTrinh", '') as "lyTrinh", COALESCE("tuyenDe", '') as "tuyenDe", "soCua", COALESCE("khauDo", '') as  "khauDo", COALESCE("kenhSauC", '') as "kenhSauC", 
					"phanLoai", COALESCE("nhiemVu", '') as "nhiemVu", COALESCE("cumQL", '0') as "cumQL", COALESCE("nguonTT", '') as "nguonTT", COALESCE("loaiCuaVan", '') as "loaiCuaVan", 
					COALESCE("mayDongMo", '') as "mayDongMo", COALESCE("dienTichPV", '0') as "dienTichPV", COALESCE("chieuRongT", '0') as "chieuRongT", COALESCE("dvql", '') as dvql, "maCT", 
					"maXa", "maTinh"
				FROM httlhp."VB_Cong"
			`

	rows, err := db.Query(sql)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	defer rows.Close()

	var ts []CongReport
	for rows.Next() {
		var t CongReport

		err := rows.Scan(&t.Id, &t.HeThong, &t.Ten, &t.ToaDoX, &t.ToaDoY,
			&t.LyTrinh, &t.TuyenDe, &t.SoCua, &t.KhauDo, &t.KenhSauC,
			&t.PhanLoai, &t.NhiemVu, &t.CumQL, &t.NguonTT, &t.LoaiCuaVan,
			&t.MayDongMo, &t.DienTichPV, &t.ChieuRongT, &t.Dvql, &t.MaCT,
			&t.MaXa, &t.MaTinh)
		if err != nil {
			continue
		}

		ts = append(ts, t)
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(ts)
	if err != nil {
		return
	}
}

func ExcelCong(db *sql.DB, w http.ResponseWriter, r *http.Request) {

	var sql = `
		SELECT id, "heThong", ten, "toaDoX", "toaDoY", 
			COALESCE("lyTrinh", '') as "lyTrinh", COALESCE("tuyenDe", '') as "tuyenDe", "soCua", COALESCE("khauDo", '') as  "khauDo", COALESCE("kenhSauC", '') as "kenhSauC", 
			"phanLoai", COALESCE("nhiemVu", '') as "nhiemVu", COALESCE("cumQL", '0') as "cumQL", COALESCE("nguonTT", '') as "nguonTT", COALESCE("loaiCuaVan", '') as "loaiCuaVan", 
			COALESCE("mayDongMo", '') as "mayDongMo", COALESCE("dienTichPV", '0') as "dienTichPV", COALESCE("chieuRongT", '0') as "chieuRongT", COALESCE("dvql", '') as dvql, "maCT", 
			"maXa", "maTinh"
		FROM httlhp."VB_Cong"
	`

	rows, err := db.Query(sql)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	var ts []CongReport
	for rows.Next() {
		var t CongReport

		err := rows.Scan(&t.Id, &t.HeThong, &t.Ten, &t.ToaDoX, &t.ToaDoY,
			&t.LyTrinh, &t.TuyenDe, &t.SoCua, &t.KhauDo, &t.KenhSauC,
			&t.PhanLoai, &t.NhiemVu, &t.CumQL, &t.NguonTT, &t.LoaiCuaVan,
			&t.MayDongMo, &t.DienTichPV, &t.ChieuRongT, &t.Dvql, &t.MaCT,
			&t.MaXa, &t.MaTinh)

		if err != nil {
			continue
		}

		ts = append(ts, t)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ts)
}
