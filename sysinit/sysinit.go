package sysinit

import (
	"errors"
	"fmt"
	"os"

	"coffee-keys-go/config"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/mattn/go-sqlite3"
)

var (
	Db *gorm.DB
)

func init() {
	var err error
	var conn string
	if config.Sysconfig.DBAdapter == "mysql" {
		conn = fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?parseTime=True&loc=Local", config.Sysconfig.DBUserName, config.Sysconfig.DBPassword, config.Sysconfig.DBIp, config.Sysconfig.DBPort, config.Sysconfig.DBName)
	} else if config.Sysconfig.DBAdapter == "postgres" {
		conn = fmt.Sprintf("postgres://%v:%v@%v/%v?sslmode=disable", config.Sysconfig.DBUserName, config.Sysconfig.DBPassword, config.Sysconfig.DBIp, config.Sysconfig.DBName)
	} else if config.Sysconfig.DBAdapter == "sqlite3" {
		conn = fmt.Sprintf("%v/%v", os.TempDir(), config.Sysconfig.DBName)
	} else {
		panic(errors.New("not supported database adapter"))
	}

	Db, err = gorm.Open(config.Sysconfig.DBAdapter, conn)
	if err != nil {
		panic(err)
	}
	Db.DB().SetMaxIdleConns(10)
	Db.DB().SetMaxOpenConns(100)
}
