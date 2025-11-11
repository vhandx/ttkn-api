package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// Models
type User struct {
	ID       int    `json:"id"`
	UserName string `json:"username"`
	Password string `json:"password,omitempty"`
	FullName string `json:"full_name"`
}

type Article struct {
	ID         int       `json:"id"`
	Title      string    `json:"title"`
	Content    string    `json:"content"`
	AuthorID   string    `json:"author_id"`
	AuthorName string    `json:"author_name"`
	ViewCount  int       `json:"view_count"`
	Status     int       `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type TtknAll struct {
	Id       string `json:"id"`
	TenHuyen string `json:"tenHuyen"`
	TenTinh  string `json:"tenTinh"`
	DtTtkn   string `json:"dtTTKN"`
	DtTtknTn string `json:"dtTTKNTN"`
	CnTTKN   string `json:"cnTTKN"`
	NangSuat string `json:"nangSuat"`
	SanLuong string `json:"sanLuong"`
}

type Ttkn struct {
	Id       int64   `json:"id"`
	TenHuyen string  `json:"tenHuyen"`
	TenTinh  string  `json:"tenTinh"`
	DtTtknTn float64 `json:"dtTTKNTN"`
	Group    string  `json:"group"`
}

type TtknR struct {
	Id       string  `json:"id"`
	TenHuyen string  `json:"tenHuyen"`
	TenTinh  string  `json:"tenTinh"`
	DtTtkn   float64 `json:"dtTTKN"`
	CnTTKN   string  `json:"cnTTKN"`
	NangSuat float64 `json:"nangSuat"`
	SanLuong float64 `json:"sanLuong"`
}

type TtknHt struct {
	Id       string `json:"id"`
	TenHuyen string `json:"tenHuyen"`
	TenTinh  string `json:"tenTinh"`
	DtTtkn   string `json:"dtTTKN"`
	CnTTKN   string `json:"cnTTKN"`
	NangSuat string `json:"nangSuat"`
	SanLuong string `json:"sanLuong"`
}

type TtknTn struct {
	Id       string  `json:"id"`
	TenHuyen string  `json:"tenHuyen"`
	TenTinh  string  `json:"tenTinh"`
	DtTtknTn float64 `json:"dtTTKNTN"`
}

type TtknAdd struct {
	Layer    string `json:"layer"`
	TenHuyen string `json:"tenHuyen"`
	TenTinh  string `json:"tenTinh"`
	DtTtkn   string `json:"dtTTKN"`
	DtTtknTN string `json:"dtTTKNTN"`
	CnTtkn   string `json:"cnTTKN"`
	NangSuat string `json:"nangSuat"`
	SanLuong string `json:"sanLuong"`
	Geometry struct {
		Type        string        `json:"type"`
		Coordinates [][][]float64 `json:"coordinates"`
	} `json:"geometry"`
}

type LoginRequest struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type Chart struct {
	Labels   []string  `json:"labels"`
	Datasets []Dataset `json:"datasets"`
}

type Dataset struct {
	Label           string    `json:"label"`
	Data            []float64 `json:"data"`
	BorderColor     string    `json:"borderColor"`
	BackgroundColor string    `json:"backgroundColor"`
	BorderWidth     int       `json:"borderWidth"`
}

// Database
var db *sql.DB

// JWT Secret
var jwtSecret = []byte("your-secret-key")

// Database connection
func initDB() {
	var err error

	//connStr := "user=postgis dbname=postgis sslmode=disable password=postgis host=localhost port=5432"
	connStr := "user=postgres dbname=postgres sslmode=disable password=postgres host=localhost port=5432"

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	log.Println("Connected to database successfully")

	// insertSampleData()
}

// Middleware
func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if r.Method == "OPTIONS" {
			return
		}

		next.ServeHTTP(w, r)
	})
}

func authenticateToken(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Handlers
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var user User
	var hashedPassword string

	users := db.QueryRow("SELECT id, username, password, full_name FROM users WHERE username = $1", req.UserName)

	err := users.Scan(&user.ID, &user.UserName, &hashedPassword, &user.FullName)

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.UserName,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	response := LoginResponse{
		Token: tokenString,
		User:  user,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// In a real application, you might want to blacklist the token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logout successful"})
}

func getUserByIdHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var user User
	err = db.QueryRow("SELECT id, username, full_name FROM users WHERE id = $1", userID).
		Scan(&user.ID, &user.UserName, &user.FullName)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func getTop10ArticlesHandler(w http.ResponseWriter, r *http.Request) {

	rows, err := db.Query(`
		SELECT a.id, a.title, a.content, a.author_id, u.full_name, a.view_count 
		FROM articles a 
		LEFT JOIN users u ON a.author_id = u.user_id 
		ORDER BY a.view_count DESC 
		LIMIT 10
	`)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var articles []Article
	for rows.Next() {
		var article Article
		err := rows.Scan(&article.ID, &article.Title, &article.Content, &article.AuthorID,
			&article.AuthorName, &article.ViewCount)
		if err != nil {
			continue
		}
		articles = append(articles, article)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(articles)
}

func getArticleByIdHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	articleID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid article ID", http.StatusBadRequest)
		return
	}

	// Increment view count
	_, err = db.Exec("UPDATE articles SET view_count = view_count + 1 WHERE id = $1", articleID)
	if err != nil {
		log.Println("Failed to increment view count:", err)
	}

	var article Article
	err = db.QueryRow(`
		SELECT a.id, a.title, a.content, a.author_id, u.full_name, a.view_count, a.created_at, a.updated_at 
		FROM articles a 
		LEFT JOIN users u ON a.author_id = u.user_id 
		WHERE a.id = $1
	`, articleID).Scan(&article.ID, &article.Title, &article.Content, &article.AuthorID,
		&article.AuthorName, &article.ViewCount, &article.CreatedAt, &article.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Article not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(article)
}

func ttknExcel(w http.ResponseWriter, r *http.Request) {

	var sql = `
		SELECT concat('VungTuoiTK_HienTrang_DBSH.',id) as id, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
			FROM public."VungTuoiTK_HienTrang_DBSH"
		union all
		SELECT concat('VungTuoiTK_HienTrang_DBSCL.',id) as id, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
			FROM public."VungTuoiTK_HienTrang_DBSCL"
		union all
		SELECT concat('VungTuoiTK_HienTrang_DNB.',id) as id, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
			FROM public."VungTuoiTK_HienTrang_DNB"
		union all
		SELECT concat('VungTuoiTK_HienTrang_TDMNPB.',id) as id, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
			FROM public."VungTuoiTK_HienTrang_TDMNPB"
		union all
		SELECT concat('VungTuoiTK_HienTrang_TN.',id) as id, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
			FROM public."VungTuoiTK_HienTrang_TN"
		union all
		SELECT concat('VungTuoiTK_HienTrang_BTB.',id) as id, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
			FROM public."VungTuoiTK_HienTrang_BTB"
		union all
		SELECT concat('VungTuoiTK_HienTrang_NTB.',id) as id, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
			FROM public."VungTuoiTK_HienTrang_NTB"
		union all
		SELECT concat('VungTuoiTK_TiemNang_DBSCL.',id) as id, "tenHuyen", "tenTinh", "dtTTKNTN" as "dtTTKN", '' as "cnTTKN", 0 as "nangSuat", 0 as "sanLuong"
			FROM public."VungTuoiTK_TiemNang_DBSCL"
		union all
		SELECT concat('VungTuoiTK_TiemNang_DBSH.',id) as id, "tenHuyen", "tenTinh", "dtTTKNTN" as "dtTTKN", '' as "cnTTKN", 0 as "nangSuat", 0 as "sanLuong"
			FROM public."VungTuoiTK_TiemNang_DBSH"
	`

	rows, err := db.Query(sql)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var ts []TtknR
	for rows.Next() {
		var t TtknR
		err := rows.Scan(&t.Id, &t.TenHuyen, &t.TenTinh, &t.DtTtkn, &t.CnTTKN, &t.NangSuat, &t.SanLuong)
		if err != nil {
			continue
		}
		ts = append(ts, t)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ts)
}

func ttknReports(w http.ResponseWriter, r *http.Request) {

	var sql = `
		
		SELECT concat('VungTuoiTK_HienTrang_DBSH.',id) as id, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
			FROM public."VungTuoiTK_HienTrang_DBSH"
		union all
		SELECT concat('VungTuoiTK_HienTrang_DBSCL.',id) as id, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
			FROM public."VungTuoiTK_HienTrang_DBSCL"
		union all
		SELECT concat('VungTuoiTK_HienTrang_DNB.',id) as id, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
			FROM public."VungTuoiTK_HienTrang_DNB"
		union all
		SELECT concat('VungTuoiTK_HienTrang_TDMNPB.',id) as id, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
			FROM public."VungTuoiTK_HienTrang_TDMNPB"
		union all
		SELECT concat('VungTuoiTK_HienTrang_TN.',id) as id, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
			FROM public."VungTuoiTK_HienTrang_TN"
		union all
		SELECT concat('VungTuoiTK_HienTrang_BTB.',id) as id, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
			FROM public."VungTuoiTK_HienTrang_BTB"
		union all
		SELECT concat('VungTuoiTK_HienTrang_NTB.',id) as id, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
			FROM public."VungTuoiTK_HienTrang_NTB"
	`

	rows, err := db.Query(sql)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var ts []TtknR
	for rows.Next() {
		var t TtknR
		err := rows.Scan(&t.Id, &t.TenHuyen, &t.TenTinh, &t.DtTtkn, &t.CnTTKN, &t.NangSuat, &t.SanLuong)
		if err != nil {
			continue
		}
		ts = append(ts, t)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ts)
}

func ttknTnReports(w http.ResponseWriter, r *http.Request) {

	var sql = `
		SELECT concat('VungTuoiTK_TiemNang_DBSCL.',id) as id, geom, "tenHuyen", "tenTinh", "dtTTKNTN"
			FROM public."VungTuoiTK_TiemNang_DBSCL"
		union all
		SELECT concat('VungTuoiTK_TiemNang_DBSH.',id) as id, geom, "tenHuyen", "tenTinh", "dtTTKNTN"
			FROM public."VungTuoiTK_TiemNang_DBSH"
	`
	rows, err := db.Query(sql)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var ts []Ttkn
	for rows.Next() {
		var t Ttkn
		err := rows.Scan(&t.Id, &t.TenHuyen, &t.TenTinh, &t.DtTtknTn, &t.Group)
		if err != nil {
			continue
		}
		ts = append(ts, t)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ts)
}

func saveHt(w http.ResponseWriter, r *http.Request) {

	// Ensure the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data TtknHt
	// Decode the JSON request body into the MyData struct
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ids := strings.Split(data.Id, ".")
	sql := ""

	switch ids[0] {
	case "VungTuoiTK_HienTrang_TDMNPB":
		sql = `UPDATE public."VungTuoiTK_HienTrang_TDMNPB" SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKN" = $3, "cnTTKN" = $4, "nangSuat" = $5, "sanLuong" = $6 WHERE id = $7`
	case "VungTuoiTK_HienTrang_DBSH":
		sql = `UPDATE public."VungTuoiTK_HienTrang_DBSH" SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKN" = $3, "cnTTKN" = $4, "nangSuat" = $5, "sanLuong" = $6 WHERE id = $7`
	case "VungTuoiTK_HienTrang_BTB":
		sql = `UPDATE public."VungTuoiTK_HienTrang_BTB" SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKN" = $3, "cnTTKN" = $4, "nangSuat" = $5, "sanLuong" = $6 WHERE id = $7`
	case "VungTuoiTK_HienTrang_NTB":
		sql = `UPDATE public."VungTuoiTK_HienTrang_NTB" SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKN" = $3, "cnTTKN" = $4, "nangSuat" = $5, "sanLuong" = $6 WHERE id = $7`
	case "VungTuoiTK_HienTrang_TN":
		sql = `UPDATE public."VungTuoiTK_HienTrang_TN" SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKN" = $3, "cnTTKN" = $4, "nangSuat" = $5, "sanLuong" = $6 WHERE id = $7`
	case "VungTuoiTK_HienTrang_DNB":
		sql = `UPDATE public."VungTuoiTK_HienTrang_DNB" SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKN" = $3, "cnTTKN" = $4, "nangSuat" = $5, "sanLuong" = $6 WHERE id = $7`
	case "VungTuoiTK_HienTrang_DBSCL":
		sql = `UPDATE public."VungTuoiTK_HienTrang_DBSCL" SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKN" = $3, "cnTTKN" = $4, "nangSuat" = $5, "sanLuong" = $6 WHERE id = $7`
	}

	_, err = db.Exec(sql, data.TenHuyen, data.TenTinh, data.DtTtkn, data.CnTTKN, data.NangSuat, data.SanLuong, ids[1])
	if err != nil {
		log.Println("Failed to increment view count:", err)
	}

	// In a real application, you might want to blacklist the token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Update successful"})
}

func saveTn(w http.ResponseWriter, r *http.Request) {

	// Ensure the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data TtknTn
	// Decode the JSON request body into the MyData struct
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ids := strings.Split(data.Id, ".")
	sql := ""

	switch ids[0] {
	case "VungTuoiTK_TiemNang_DBSCL":
		sql = `UPDATE public."VungTuoiTK_TiemNang_DBSCL" SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKNTN" = $3 WHERE id = $4`
	case "VungTuoiTK_TiemNang_DBSH":
		sql = `UPDATE public."VungTuoiTK_TiemNang_DBSH" SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKNTN" = $3 WHERE id = $4`
	case "VungTuoiTK_TiemNang_BTB":
		sql = `UPDATE public."VungTuoiTK_TiemNang_BTB" SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKNTN" = $3 WHERE id = $4`
	case "VungTuoiTK_TiemNang_NTB":
		sql = `UPDATE public."VungTuoiTK_TiemNang_NTB" SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKNTN" = $3 WHERE id = $4`
	}

	_, err = db.Exec(sql, data.TenHuyen, data.TenTinh, data.DtTtknTn, ids[1])
	if err != nil {
		log.Println("Failed to increment view count:", err)
	}

	// In a real application, you might want to blacklist the token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Update successful"})
}

func saveTtkn(w http.ResponseWriter, r *http.Request) {

	// Ensure the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data TtknAll
	// Decode the JSON request body into the MyData struct
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	aId := strings.Split(data.Id, ".")
	query := ""

	t := 1

	switch aId[0] {

	case "VungTuoiTK_HienTrang_TDMNPB":
		query = `
			UPDATE public."VungTuoiTK_HienTrang_TDMNPB" 
				SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKN" = $3, "cnTTKN" = $4, "nangSuat" = $5, "sanLuong" = $6
			WHERE id = $7
		`
	case "VungTuoiTK_HienTrang_DBSH":
		query = `
			UPDATE public."VungTuoiTK_HienTrang_DBSH" 
				SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKN" = $3, "cnTTKN" = $4, "nangSuat" = $5, "sanLuong" = $6
			WHERE id = $7
		`
	case "VungTuoiTK_HienTrang_BTB":
		query = `
			UPDATE public."VungTuoiTK_HienTrang_BTB" 
				SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKN" = $3, "cnTTKN" = $4, "nangSuat" = $5, "sanLuong" = $6
			WHERE id = $7
		`
	case "VungTuoiTK_HienTrang_NTB":
		query = `
			UPDATE public."VungTuoiTK_HienTrang_NTB" 
				SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKN" = $3, "cnTTKN" = $4, "nangSuat" = $5, "sanLuong" = $6
			WHERE id = $7
		`
	case "VungTuoiTK_HienTrang_TN":
		query = `
			UPDATE public."VungTuoiTK_HienTrang_TN" 
				SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKN" = $3, "cnTTKN" = $4, "nangSuat" = $5, "sanLuong" = $6
			WHERE id = $7
		`
	case "VungTuoiTK_HienTrang_DNB":
		query = `
			UPDATE public."VungTuoiTK_HienTrang_DNB" 
				SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKN" = $3, "cnTTKN" = $4, "nangSuat" = $5, "sanLuong" = $6
			WHERE id = $7
		`
	case "VungTuoiTK_HienTrang_DBSCL":
		query = `
			UPDATE public."VungTuoiTK_HienTrang_DBSCL" 
				SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKN" = $3, "cnTTKN" = $4, "nangSuat" = $5, "sanLuong" = $6
			WHERE id = $7
		`
	case "VungTuoiTK_TiemNang_DBSH":
		query = `
			UPDATE public."VungTuoiTK_TiemNang_DBSH" 
				SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKNTN" = $3 
			WHERE id = $4
		`
		t = 2
	case "VungTuoiTK_TiemNang_BTB":
		query = `
			UPDATE public."VungTuoiTK_TiemNang_BTB" 
				SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKNTN" = $3 
			WHERE id = $4
		`
		t = 2
	case "VungTuoiTK_TiemNang_NTB":
		query = `
			UPDATE public."VungTuoiTK_TiemNang_NTB" 
				SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKNTN" = $3 
			WHERE id = $4
		`
		t = 2
	case "VungTuoiTK_TiemNang_DBSCL":
		query = `
			UPDATE public."VungTuoiTK_TiemNang_DBSCL" 
				SET "tenHuyen" = $1, "tenTinh" = $2, "dtTTKNTN" = $3 
			WHERE id = $4
		`
		t = 2
	}

	switch t {
	case 1:
		_, err = db.Exec(query, data.TenHuyen, data.TenTinh, data.DtTtkn, data.CnTTKN, data.NangSuat, data.SanLuong, aId[1])

	case 2:
		_, err = db.Exec(query, data.TenHuyen, data.TenTinh, data.DtTtknTn, aId[1])

	}

	if err != nil {
		log.Println("Failed to Insert:", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Update successful"})
}

func mapTtkn(w http.ResponseWriter, r *http.Request) {

	// Ensure the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data TtknAdd
	// Decode the JSON request body into the MyData struct
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	query := ""
	t := 1

	switch data.Layer {
	case "VungTuoiTK_HienTrang_BTB":
		query = `INSERT INTO public."VungTuoiTK_HienTrang_BTB" (geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong") VALUES (ST_Multi(ST_SetSRID(ST_GeomFromGeoJSON($1),4326)), $2, $3, $4, $5, $6, $7)`
	case "VungTuoiTK_HienTrang_DBSCL":
		query = `INSERT INTO public."VungTuoiTK_HienTrang_DBSCL" (geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong") VALUES (ST_Multi(ST_SetSRID(ST_GeomFromGeoJSON($1),4326)), $2, $3, $4, $5, $6, $7)`
	case "VungTuoiTK_HienTrang_DBSH":
		query = `INSERT INTO public."VungTuoiTK_HienTrang_DBSH" (geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong") VALUES (ST_Multi(ST_SetSRID(ST_GeomFromGeoJSON($1),4326)), $2, $3, $4, $5, $6, $7)`
	case "VungTuoiTK_HienTrang_DNB":
		query = `INSERT INTO public."VungTuoiTK_HienTrang_DNB" (geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong") VALUES (ST_Multi(ST_SetSRID(ST_GeomFromGeoJSON($1),4326)), $2, $3, $4, $5, $6, $7)`
	case "VungTuoiTK_HienTrang_NTB":
		query = `INSERT INTO public."VungTuoiTK_HienTrang_NTB" (geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong") VALUES (ST_Multi(ST_SetSRID(ST_GeomFromGeoJSON($1),4326)), $2, $3, $4, $5, $6, $7)`
	case "VungTuoiTK_HienTrang_TDMNPB":
		query = `INSERT INTO public."VungTuoiTK_HienTrang_TDMNPB" (geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong") VALUES (ST_Multi(ST_SetSRID(ST_GeomFromGeoJSON($1),4326)), $2, $3, $4, $5, $6, $7)`
	case "VungTuoiTK_HienTrang_TN":
		query = `INSERT INTO public."VungTuoiTK_HienTrang_TN" (geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong") VALUES (ST_Multi(ST_SetSRID(ST_GeomFromGeoJSON($1),4326)), $2, $3, $4, $5, $6, $7)`

	case "VungTuoiTK_TiemNang_BTB":
		query = `INSERT INTO public."VungTuoiTK_TiemNang_BTB" (geom, "tenHuyen", "tenTinh", "dtTTKNTN") VALUES (ST_Multi(ST_SetSRID(ST_GeomFromGeoJSON($1),4326)), $2, $3, $4)`
		t = 2
	case "VungTuoiTK_TiemNang_DBSCL":
		query = `INSERT INTO public."VungTuoiTK_TiemNang_DBSCL" (geom, "tenHuyen", "tenTinh", "dtTTKNTN") VALUES (ST_Multi(ST_SetSRID(ST_GeomFromGeoJSON($1),4326)), $2, $3, $4)`
		t = 2
	case "VungTuoiTK_TiemNang_DBSH":
		query = `INSERT INTO public."VungTuoiTK_TiemNang_DBSH" (geom, "tenHuyen", "tenTinh", "dtTTKNTN") VALUES (ST_Multi(ST_SetSRID(ST_GeomFromGeoJSON($1),4326)), $2, $3, $4)`
		t = 2
	case "VungTuoiTK_TiemNang_NTB":
		query = `INSERT INTO public."VungTuoiTK_TiemNang_NTB" (geom, "tenHuyen", "tenTinh", "dtTTKNTN") VALUES (ST_Multi(ST_SetSRID(ST_GeomFromGeoJSON($1),4326)), $2, $3, $4)`
		t = 2
	}

	geo, err := json.Marshal(data.Geometry)
	if err != nil {
		fmt.Println("Error Marshal JSON:", err)
		return
	}
	switch t {
	case 1:
		_, err = db.Exec(query, string(geo), data.TenHuyen, data.TenTinh, data.DtTtkn, data.CnTtkn, data.NangSuat, data.SanLuong)

	case 2:
		_, err = db.Exec(query, string(geo), data.TenHuyen, data.TenTinh, data.DtTtknTN)

	}

	if err != nil {
		log.Println("Failed to Insert:", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Insert successful"})
}

func deleteTtkn(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ttknId := (vars["id"])

	aId := strings.Split(ttknId, ".")
	query := ""
	queryD := ""

	switch aId[0] {

	case "VungTuoiTK_HienTrang_TDMNPB":
		query = `
			INSERT INTO public."VungTuoiTK_HienTrang_Backup"(ref_id, geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong")
			SELECT id, geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
				FROM public."VungTuoiTK_HienTrang_TDMNPB" WHERE Id = $1
		`
		queryD = `DELETE FROM public."VungTuoiTK_HienTrang_TDMNPB" WHERE Id = $1`
	case "VungTuoiTK_HienTrang_DBSH":
		query = `
			INSERT INTO public."VungTuoiTK_HienTrang_Backup"(ref_id, geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong")
			SELECT id, geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
				FROM public."VungTuoiTK_HienTrang_DBSH" WHERE Id = $1
		`
		queryD = `DELETE FROM public."VungTuoiTK_HienTrang_DBSH" WHERE Id = $1`
	case "VungTuoiTK_HienTrang_BTB":
		query = `
			INSERT INTO public."VungTuoiTK_HienTrang_Backup"(ref_id, geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong")
			SELECT id, geom, ""tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
				FROM public."VungTuoiTK_HienTrang_BTB" WHERE Id = $1
		`
		queryD = `DELETE FROM public."VungTuoiTK_HienTrang_BTB" WHERE Id = $1`
	case "VungTuoiTK_HienTrang_NTB":
		query = `
			INSERT INTO public."VungTuoiTK_HienTrang_Backup"(ref_id, geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong")
			SELECT id, geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
				FROM public."VungTuoiTK_HienTrang_NTB" WHERE Id = $1
		`
		queryD = `DELETE FROM public."VungTuoiTK_HienTrang_NTB" WHERE Id = $1`
	case "VungTuoiTK_HienTrang_TN":
		query = `
			INSERT INTO public."VungTuoiTK_HienTrang_Backup"(ref_id, geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong")
			SELECT id, geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
				FROM public."VungTuoiTK_HienTrang_TN" WHERE Id = $1
		`
		queryD = `DELETE FROM public."VungTuoiTK_HienTrang_TN" WHERE Id = $1`
	case "VungTuoiTK_HienTrang_DNB":
		query = `
			INSERT INTO public."VungTuoiTK_HienTrang_Backup"(ref_id, geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong")
			SELECT id, geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
				FROM public."VungTuoiTK_HienTrang_DNB" WHERE Id = $1
		`
		queryD = `DELETE FROM public."VungTuoiTK_HienTrang_DNB" WHERE Id = $1`
	case "VungTuoiTK_HienTrang_DBSCL":
		query = `
			INSERT INTO public."VungTuoiTK_HienTrang_Backup"(ref_id, geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong")
			SELECT id, geom, "tenHuyen", "tenTinh", "dtTTKN", "cnTTKN", "nangSuat", "sanLuong"
				FROM public."VungTuoiTK_HienTrang_DBSCL" WHERE Id = $1
		`
		queryD = `DELETE FROM public."VungTuoiTK_HienTrang_DBSCL" WHERE Id = $1`
	case "VungTuoiTK_TiemNang_DBSH":
		query = `
			INSERT INTO public."VungTuoiTK_TiemNang_Backup"(ref_id, geom, "tenHuyen", "tenTinh", "dtTTKNTN")
			SELECT id, geom, "tenHuyen", "tenTinh", "dtTTKNTN"
				FROM public."VungTuoiTK_TiemNang_DBSH" WHERE Id = $1
		`
		queryD = `DELETE FROM public."VungTuoiTK_TiemNang_DBSH" WHERE Id = $1`
	case "VungTuoiTK_TiemNang_BTB":
		query = `
			INSERT INTO public."VungTuoiTK_TiemNang_Backup"(ref_id, geom, "tenHuyen", "tenTinh", "dtTTKNTN")
			SELECT id, geom, "tenHuyen", "tenTinh", "dtTTKNTN"
				FROM public."VungTuoiTK_TiemNang_BTB" WHERE Id = $1
		`
		queryD = `DELETE FROM public."VungTuoiTK_TiemNang_BTB" WHERE Id = $1`
	case "VungTuoiTK_TiemNang_NTB":
		query = `
			INSERT INTO public."VungTuoiTK_TiemNang_Backup"(ref_id, geom, "tenHuyen", "tenTinh", "dtTTKNTN")
			SELECT id, geom, "tenHuyen", "tenTinh", "dtTTKNTN"
				FROM public."VungTuoiTK_TiemNang_NTB" WHERE Id = $1
		`
		queryD = `DELETE FROM public."VungTuoiTK_TiemNang_NTB" WHERE Id = $1`
	case "VungTuoiTK_TiemNang_DBSCL":
		query = `
			INSERT INTO public."VungTuoiTK_TiemNang_Backup"(ref_id, geom, "tenHuyen", "tenTinh", "dtTTKNTN")
			SELECT id, geom, "tenHuyen", "tenTinh", "dtTTKNTN"
				FROM public."VungTuoiTK_TiemNang_DBSCL" WHERE Id = $1
		`
		queryD = `DELETE FROM public."VungTuoiTK_TiemNang_DBSCL" WHERE Id = $1`
	}

	_, err := db.Exec(query, aId[1])

	if err != nil {
		http.Error(w, "Backup error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(queryD, aId[1])

	if err != nil {
		http.Error(w, "Delete error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Delete successful"})
}

func ttknChart01(w http.ResponseWriter, r *http.Request) {

	var sql = `
		SELECT "tenTinh", sum("dtTTKN") as "TongDienTichTTKN"
			FROM public."VungTuoiTK_HienTrang_DBSH"
		GROUP BY "tenTinh"
		ORDER BY "tenTinh"
	`

	rows, err := db.Query(sql)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	defer rows.Close()

	var labels []string
	var data []float64

	var chart Chart
	var dataset Dataset

	for rows.Next() {
		label := ""
		value := 0.0

		rows.Scan(&label, &value)

		labels = append(labels, label)
		data = append(data, value)

	}

	dataset.Label = "Tổng diện tích Tưới tiết kiệm nước theo Tỉnh tại Vùng Đồng bằng Sông Hồng"
	dataset.BackgroundColor = "#5FC3D6"
	dataset.BorderColor = "#5FC3D6"
	dataset.BorderWidth = 1
	dataset.Data = data

	chart.Labels = labels
	chart.Datasets = []Dataset{dataset}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(chart)
}

func ttknChart02(w http.ResponseWriter, r *http.Request) {

	var sql = `
		SELECT "cnTTKN", sum("dtTTKN")
			FROM public."VungTuoiTK_HienTrang_DBSH"
		WHERE "cnTTKN" IS NOT NULL
		GROUP BY "cnTTKN"
		ORDER BY "cnTTKN"
	`

	rows, err := db.Query(sql)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	defer rows.Close()

	var labels []string
	var data []float64

	var chart Chart
	var dataset Dataset

	for rows.Next() {
		label := ""
		value := 0.0

		rows.Scan(&label, &value)

		labels = append(labels, label)
		data = append(data, value)

	}

	dataset.Label = "Tổng diện tích theo Công nghệ tưới"
	dataset.BackgroundColor = "#198754"
	dataset.BorderColor = "#198754"
	dataset.BorderWidth = 1
	dataset.Data = data

	chart.Labels = labels
	chart.Datasets = []Dataset{dataset}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(chart)
}

func main() {

	// Initialize database
	initDB()
	defer db.Close()

	// Setup routes
	r := mux.NewRouter()

	// User API
	r.HandleFunc("/api/auth/login", loginHandler).Methods("POST")
	r.HandleFunc("/api/auth/logout", authenticateToken(logoutHandler)).Methods("POST")
	r.HandleFunc("/api/users/{id:[0-9]+}", authenticateToken(getUserByIdHandler)).Methods("GET")

	// Article API
	r.HandleFunc("/api/articles/top", getTop10ArticlesHandler).Methods("GET")
	r.HandleFunc("/api/articles/{id:[0-9]+}", getArticleByIdHandler).Methods("GET")

	// TTKN API
	r.HandleFunc("/api/ttkn/excel", authenticateToken(ttknExcel)).Methods("GET")
	r.HandleFunc("/api/ttkn/reports", authenticateToken(ttknReports)).Methods("GET")
	r.HandleFunc("/api/ttkn/report", ttknReports).Methods("GET")
	r.HandleFunc("/api/ttkntn/reports", authenticateToken(ttknTnReports)).Methods("GET")

	r.HandleFunc("/api/ttkn/ht", authenticateToken(saveHt)).Methods("POST")
	r.HandleFunc("/api/ttkn/tn", authenticateToken(saveTn)).Methods("POST")

	// Map action
	r.HandleFunc("/api/ttkn", authenticateToken(saveTtkn)).Methods("POST")
	r.HandleFunc("/api/map", authenticateToken(mapTtkn)).Methods("POST")

	r.HandleFunc("/api/ttkn/{id}", authenticateToken(deleteTtkn)).Methods("DELETE")

	//Chart
	r.HandleFunc("/api/ttkn/chart01", ttknChart01).Methods("GET")
	r.HandleFunc("/api/ttkn/chart02", ttknChart02).Methods("GET")

	// Apply CORS middleware
	handler := enableCORS(r)

	fmt.Println("Server starting on port 8787...")
	log.Fatal(http.ListenAndServe(":8787", handler))

}
