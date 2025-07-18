package database

import (
	"auth-service/model/testdata"
	
	"fmt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func Testdata(db *gorm.DB) {
	err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&testdata.UserTestData).Error
	if err != nil {
		fmt.Println("Failed to seed users:", err)
	}

}