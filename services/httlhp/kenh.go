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

type Kenh struct {
	Id        string  `json:"id"`
	ObjectId  string  `json:"OBJECTID"`
	HeThong   string  `json:"He_thong"`
	TenKenh   string  `json:"Ten_kenh"`
	ChieuDai  float64 `json:"Chieu_dai"`
	KTB       float64 `json:"KT_b"`
	KTH       float64 `json:"KT_h"`
	KTM       float64 `json:"KT_m"`
	KetCau    string  `json:"Ket_cau"`
	DiemDau   string  `json:"Diem_dau"`
	DiemCuoi  string  `json:"Diem_cuoi"`
	Xa        string  `json:"Xa"`
	Huyen     string  `json:"Huyen"`
	GhiChu    string  `json:"Ghi_chu"`
	CQQL      string  `json:"CQQL"`
	SHAPELeng float64 `json:"SHAPE_Leng"`
	LoaiKenh  string  `json:"Loai_kenh"`
}
type MapKenhAdd struct {
	Layer     string `json:"layer"`
	ObjectId  string `json:"OBJECTID"`
	HeThong   string `json:"He_thong"`
	TenKenh   string `json:"Ten_kenh"`
	ChieuDai  string `json:"Chieu_dai"`
	KTB       string `json:"KT_b"`
	KTH       string `json:"KT_h"`
	KTM       string `json:"KT_m"`
	KetCau    string `json:"Ket_cau"`
	DiemDau   string `json:"Diem_dau"`
	DiemCuoi  string `json:"Diem_cuoi"`
	Xa        string `json:"Xa"`
	Huyen     string `json:"Huyen"`
	GhiChu    string `json:"Ghi_chu"`
	CQQL      string `json:"CQQL"`
	SHAPELeng string `json:"SHAPE_Leng"`
	LoaiKenh  string `json:"Loai_kenh"`
	Geometry  struct {
		Type        string        `json:"type"`
		Coordinates [][][]float64 `json:"coordinates"`
	} `json:"geometry"`
}
type KenhReport struct {
	Id        string `json:"id"`
	ObjectId  string `json:"OBJECTID"`
	HeThong   string `json:"He_thong"`
	TenKenh   string `json:"Ten_kenh"`
	ChieuDai  string `json:"Chieu_dai"`
	KTB       string `json:"KT_b"`
	KTH       string `json:"KT_h"`
	KTM       string `json:"KT_m"`
	KetCau    string `json:"Ket_cau"`
	DiemDau   string `json:"Diem_dau"`
	DiemCuoi  string `json:"Diem_cuoi"`
	Xa        string `json:"Xa"`
	Huyen     string `json:"Huyen"`
	GhiChu    string `json:"Ghi_chu"`
	CQQL      string `json:"CQQL"`
	SHAPELeng string `json:"SHAPE_Leng"`
	LoaiKenh  string `json:"Loai_kenh"`
}

func SaveKenh(db *sql.DB, w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data Kenh
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	aId := strings.Split(data.Id, ".")

	query := `
			UPDATE httlhp."VB_Kenh"
				SET "He_thong"=$1, "Ten_kenh"=$2, "Chieu_dai"=$3, "KT_b"=$4, 
				    "KT_h"=$5, "KT_m"=$6, "Ket_cau"=$7, "Diem_dau"=$8, "Diem_cuoi"=$9, 
				    "Xa"=$10, "Huyen"=$11, "Ghi_chu"=$12, "CQQL"=$13, "SHAPE_Leng"=$14, "Loai_kenh"=$15
			WHERE id = $16
		`

	//chieu_dai, _ := strconv.ParseFloat(data.ChieuDai, 64)
	//ktb, _ := strconv.ParseFloat(data.KTB, 64)
	//kth, _ := strconv.ParseFloat(data.KTH, 64)
	//ktm, _ := strconv.ParseFloat(data.KTM, 64)
	//shape_leng, _ := strconv.ParseFloat(data.SHAPELeng, 64)

	_, err = db.Exec(query, data.HeThong, data.TenKenh, data.ChieuDai, data.KTB,
		data.KTH, data.KTM, data.KetCau, data.DiemDau, data.DiemCuoi,
		data.Xa, data.Huyen, data.GhiChu, data.CQQL, data.SHAPELeng, data.LoaiKenh, aId[1])

	if err != nil {
		log.Println("Failed to Insert:", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Update successful"})
}

func MapKenh(db *sql.DB, w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data MapKenhAdd
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	query := `INSERT INTO httlhp."VB_Kenh" 
				(geom, "OBJECTID", "He_thong", "Ten_kenh", "Chieu_dai", 
				 "KT_b", "KT_h", "KT_m", "Ket_cau", "Diem_dau", 
				 "Diem_cuoi", "Xa", "Huyen", "Ghi_chu", "CQQL", 
				 "SHAPE_Leng", "Loai_kenh")
			VALUES (ST_Multi(ST_SetSRID(ST_GeomFromGeoJSON($1),4326)), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`

	geo, err := json.Marshal(data.Geometry)
	if err != nil {
		fmt.Println("Error Marshal JSON:", err)
		return
	}

	objectId, _ := strconv.ParseInt(data.ObjectId, 10, 64)
	chieuDai, _ := strconv.ParseFloat(data.ChieuDai, 64)
	ktB, _ := strconv.ParseFloat(data.KTB, 64)
	ktH, _ := strconv.ParseFloat(data.KTH, 64)
	ktM, _ := strconv.ParseFloat(data.KTM, 64)
	shapeLeng, _ := strconv.ParseFloat(data.SHAPELeng, 64)

	_, err = db.Exec(query, string(geo), objectId, data.HeThong, data.TenKenh, chieuDai,
		ktB, ktH, ktM, data.KetCau, data.DiemDau,
		data.DiemCuoi, data.Xa, data.Huyen, data.GhiChu, data.CQQL,
		shapeLeng, data.LoaiKenh)

	if err != nil {
		log.Println("Failed to Insert:", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Insert successful"})
}

func ReportVbKenh(db *sql.DB, w http.ResponseWriter, r *http.Request) {

	var sql = `
		SELECT id, "OBJECTID", "He_thong", "Ten_kenh", "Chieu_dai", "KT_b", "KT_h", "KT_m", 
		       "Ket_cau", COALESCE("Diem_dau", '') as "Diem_dau", COALESCE("Diem_cuoi", '') as "Diem_cuoi", COALESCE("Xa", '') as "Xa", COALESCE("Huyen", '') as "Huyen", COALESCE("Ghi_chu", '') as "Ghi_chu", "CQQL", "SHAPE_Leng", "Loai_kenh"
		FROM httlhp."VB_Kenh"
	`

	rows, err := db.Query(sql)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	defer rows.Close()

	var ts []KenhReport
	for rows.Next() {
		var t KenhReport

		err := rows.Scan(&t.Id, &t.ObjectId, &t.HeThong, &t.TenKenh, &t.ChieuDai, &t.KTB, &t.KTH, &t.KTM, &t.KetCau, &t.DiemDau, &t.DiemCuoi, &t.Xa, &t.Huyen, &t.GhiChu, &t.CQQL, &t.SHAPELeng, &t.LoaiKenh)
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

func ExcelKenh(db *sql.DB, w http.ResponseWriter, r *http.Request) {

	var sql = `
		SELECT id, "OBJECTID", "He_thong", COALESCE("Ten_kenh", ''), "Chieu_dai", "KT_b", "KT_h", "KT_m", 
		       "Ket_cau", COALESCE("Diem_dau", '') as "Diem_dau", COALESCE("Diem_cuoi", '') as "Diem_cuoi", COALESCE("Xa", '') as "Xa", COALESCE("Huyen", '') as "Huyen", COALESCE("Ghi_chu", '') as "Ghi_chu", "CQQL", "SHAPE_Leng", "Loai_kenh"
		FROM httlhp."VB_Kenh"
	`

	rows, err := db.Query(sql)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	var ts []KenhReport
	for rows.Next() {
		var t KenhReport

		err := rows.Scan(&t.Id, &t.ObjectId, &t.HeThong, &t.TenKenh, &t.ChieuDai, &t.KTB, &t.KTH, &t.KTM, &t.KetCau, &t.DiemDau, &t.DiemCuoi, &t.Xa, &t.Huyen, &t.GhiChu, &t.CQQL, &t.SHAPELeng, &t.LoaiKenh)
		if err != nil {
			continue
		}

		ts = append(ts, t)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ts)
}
