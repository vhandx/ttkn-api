package httlhp

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type TramBom struct {
	Id         string  `json:"id"`
	ObjectId   string  `json:"OBJECTID"`
	HeThong    string  `json:"He_thong"`
	TenTB      string  `json:"Ten_TB"`
	DiaDiem    string  `json:"Dia_diem"`
	ToaDoX     float64 `json:"Toa_do_X"`
	ToaDoY     float64 `json:"Toa_do_Y"`
	SoMay      int64   `json:"So_may"`
	LuuLuongTK int64   `json:"LuuLuongTK"`
	GhiChu     string  `json:"Ghi_chu"`
}

type MapTramBomAdd struct {
	Layer      string `json:"layer"`
	ObjectId   string `json:"OBJECTID"`
	HeThong    string `json:"He_thong"`
	TenTB      string `json:"Ten_TB"`
	DiaDiem    string `json:"Dia_diem"`
	ToaDoX     string `json:"Toa_do_X"`
	ToaDoY     string `json:"Toa_do_Y"`
	SoMay      string `json:"So_may"`
	LuuLuongTK string `json:"LuuLuongTK"`
	GhiChu     string `json:"Ghi_chu"`
	Geometry   struct {
		Type        string    `json:"type"`
		Coordinates []float64 `json:"coordinates"`
	} `json:"geometry"`
}

type TramBomReport struct {
	Id         string `json:"id"`
	ObjectId   string `json:"OBJECTID"`
	HeThong    string `json:"He_thong"`
	TenTB      string `json:"Ten_TB"`
	DiaDiem    string `json:"Dia_diem"`
	ToaDoX     string `json:"Toa_do_X"`
	ToaDoY     string `json:"Toa_do_Y"`
	SoMay      string `json:"So_may"`
	LuuLuongTK string `json:"LuuLuongTK"`
	GhiChu     string `json:"Ghi_chu"`
}

func SaveTramBom(db *sql.DB, w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data TramBom
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	aId := strings.Split(data.Id, ".")

	query := `
			UPDATE httlhp."VB_TramBom"
				SET "He_thong"=$1, "Ten_TB"=$2, "Dia_diem"=$3, "Toa_do_X"=$4, 
				    "Toa_do_Y"=$5, "So_may"=$6, "LuuLuongTK"=$7, "Ghi_chu"=$8
			WHERE id = $9
		`

	_, err = db.Exec(query, data.HeThong, data.TenTB, data.DiaDiem, data.ToaDoX,
		data.ToaDoY, data.SoMay, data.LuuLuongTK, data.GhiChu, aId[1])

	if err != nil {
		log.Println("Failed to Insert:", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Update successful"})
}

func MapTramBom(db *sql.DB, w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data MapTramBomAdd

	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	query := `INSERT INTO httlhp."VB_TramBom" (geom, "OBJECTID", "He_thong", "Ten_TB", "Dia_diem", "Toa_do_X", "Toa_do_Y", "So_may", "LuuLuongTK", "Ghi_chu") 
				VALUES (ST_GeomFromGeoJSON($1)::geometry(Point, 4326), $2, $3, $4, $5, $6, $7, $8, $9, $10)
			`

	geo, err := json.Marshal(data.Geometry)
	if err != nil {
		fmt.Println("Error Marshal JSON:", err)
		return
	}

	objectId, _ := strconv.ParseInt(data.ObjectId, 10, 64)
	toaDoX, _ := strconv.ParseFloat(data.ToaDoX, 64)
	toaDoY, _ := strconv.ParseFloat(data.ToaDoY, 64)
	soMay, _ := strconv.ParseInt(data.SoMay, 10, 64)
	luuLuongTK, _ := strconv.ParseInt(data.LuuLuongTK, 10, 64)

	_, err = db.Exec(query, string(geo), objectId, data.HeThong, data.TenTB, data.DiaDiem, toaDoX, toaDoY, soMay, luuLuongTK, data.GhiChu)

	if err != nil {
		log.Println("Failed to Insert:", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Insert successful"})
}

func ReportVbTramBom(db *sql.DB, w http.ResponseWriter, r *http.Request) {

	var sql = `
		SELECT id, "OBJECTID", "He_thong", "Ten_TB", COALESCE("Dia_diem", '') as "Dia_diem", "Toa_do_X", "Toa_do_Y", 
		       "So_may", "LuuLuongTK",  COALESCE("Ghi_chu", '') as  "Ghi_chu"
		FROM httlhp."VB_TramBom"
	`

	rows, err := db.Query(sql)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	defer rows.Close()

	var ts []TramBomReport
	for rows.Next() {
		var t TramBomReport

		err := rows.Scan(&t.Id, &t.ObjectId, &t.HeThong, &t.TenTB, &t.DiaDiem, &t.ToaDoX, &t.ToaDoY, &t.SoMay, &t.LuuLuongTK, &t.GhiChu)
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

func ExcelTramBom(db *sql.DB, w http.ResponseWriter, r *http.Request) {

	var sql = `
		SELECT id, "OBJECTID", "He_thong", "Ten_TB", COALESCE("Dia_diem", '') as "Dia_diem", "Toa_do_X", "Toa_do_Y", 
		       "So_may", "LuuLuongTK",  COALESCE("Ghi_chu", '') as  "Ghi_chu"
		FROM httlhp."VB_TramBom"
	`

	rows, err := db.Query(sql)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	defer rows.Close()

	var ts []TramBomReport
	for rows.Next() {
		var t TramBomReport

		err := rows.Scan(&t.Id, &t.ObjectId, &t.HeThong, &t.TenTB, &t.DiaDiem, &t.ToaDoX, &t.ToaDoY, &t.SoMay, &t.LuuLuongTK, &t.GhiChu)
		if err != nil {
			continue
		}

		ts = append(ts, t)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ts)
}
