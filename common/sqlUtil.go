package common

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func SqliteConnect() *gorm.DB {
	db, err := gorm.Open(sqlite.Open(O_sqlite_db), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	// 迁移 schema
	err = db.AutoMigrate(&HostInfo{})
	if err != nil {
		return nil
	}
	err = db.AutoMigrate(&PortInfo{})
	if err != nil {
		return nil
	}
	return db
}

func InsertSqlite(hostInfo HostInfo, pInfo []PortInfo) {
	//创建数据库连接
	db := SqliteConnect()
	//写入sqlite
	db.Create(&hostInfo)
	for _, portInfo := range pInfo {
		db.Create(&portInfo)
	}
}
