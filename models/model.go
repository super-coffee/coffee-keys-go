package models

import (
	"coffee-keys-go/sysinit"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"regexp"
	"strings"
	"time"
)

// 用户表
type User struct {
	Id       int    `gorm:"primary_key" json:"id"`
	Name     string `gorm:"unique;VARCHAR(191)" json:"name"`
	Mail     string `gorm:"unique;VARCHAR(191)" json:"mail"`
	Password string `gorm:"not null VARCHAR(191)" json:"password"`
	Date     time.Time
	Role     int
}

// 密匙表
type Pubkey struct {
	Id     int       `gorm:"primary_key" json:"id"`
	U_id   int       `json:"u_id"`
	Pubkey string    `gorm:"unique;VARCHAR(191)" json:"pubkey"`
	Info   string    `gorm:"unique;VARCHAR(191)" json:"info"`
	Date   time.Time `json:"date"`
}

// 设置表
type Setting struct {
	Id   int    `gorm:"primary_key" json:"id"`
	Name string `gorm:"unique;VARCHAR(191)" json:"name"`
	Data string `gorm:"unique;VARCHAR(191)" json:"data"`
}

// 通过邮箱获取用户
func GetUserByMail(mail string) (User, error) {
	var user User
	m := sysinit.Db.Where("mail = ?", mail).First(&user)
	if m.Error != nil {
		return user, m.Error
	}
	return user, nil
}

// 通过邮箱获取密匙
func GetKeyByMail(mail string) ([]Pubkey, error) {
	var pubkeys []Pubkey
	user, err := GetUserByMail(mail)
	if err != nil {
		return nil, err
	}
	m := sysinit.Db.Where("u_id = ?", user.Id).Find(&pubkeys)
	if m.Error != nil {
		return nil, m.Error
	}
	return pubkeys, nil
}

// 通过Key的ID获取密匙
func GetKeyById(id int) (Pubkey, error) {
	var pubkey Pubkey
	m := sysinit.Db.Where("id = ?", id).First(&pubkey)
	if m.Error != nil {
		return Pubkey{}, m.Error
	}
	return pubkey, nil
}

// 验证用户密码
func VerifyPassword(mail, password string) (User, error) {
	user, err := GetUserByMail(mail)
	if err != nil {
		return user, err
	} else {
		if CheckPassword(user.Password, password) {
			return user, nil
		} else {
			return User{}, errors.New("用户名密码不正确")
		}

	}
}

// 新建key
func CreateKey(u_id int, publickey, info string) error {
	key := Pubkey{
		Info:   info,
		Date:   time.Now(),
		Pubkey: publickey,
		U_id:   u_id,
	}
	return sysinit.Db.Create(&key).Error
}

// 安全地删除key
func DelKeyByIdSafe(id int, mail string) (string, error) {
	user, err := GetUserByMail(mail)
	if err != nil {
		return "非法！", err
	} else {
		key, err := GetKeyById(id)
		if err != nil {
			return "key不存在", err
		}
		if key.U_id == user.Id {
			d_key := Pubkey{Id: key.Id}
			m := sysinit.Db.Delete(&d_key)
			if m.Error != nil {
				return "删除失败", m.Error
			}
			return "删除成功", nil
		} else {
			return "非法删除", errors.New("非法删除")
		}
	}

}

// Hash密码
func HashPassword(str string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(str), bcrypt.DefaultCost)
	return base64.StdEncoding.EncodeToString(hash), err
}

// 检查密码是否与Hash密码匹配
func CheckPassword(oldHash, newPassword string) bool {
	decodeBytes, _ := base64.StdEncoding.DecodeString(oldHash)
	err := bcrypt.CompareHashAndPassword(decodeBytes, []byte(newPassword))
	if err != nil {
		return false
	} else {
		return true
	}
}

// 用户注册函数
func Register(name, mail, password, password2 string) error {
	isok, err := regexp.Match(`^[A-Za-z0-9]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+$`, []byte(mail))
	if err != nil {
		return err
	}
	if !isok {
		return errors.New("邮箱格式错误")
	}
	if password == "" || password2 == "" || name == "" || mail == "" {
		return errors.New("表格请填写完整")
	}
	if password != password2 {
		return errors.New("两次密码不一致！")
	}
	_, err = GetUserByMail(mail)
	if err == nil {
		return errors.New("邮箱已经有人注册了！")
	}
	hashpassword, err := HashPassword(password)
	if err != nil {
		return err
	}

	user := User{
		Mail:     mail,
		Date:     time.Now(),
		Password: hashpassword,
		Name:     strings.ReplaceAll(name, " ", ""),
	}
	return sysinit.Db.Create(&user).Error
}

// 修改名称或密码
func EditUser(mail, oldpassword, newname, newpassword string) error {
	if newname == "" && oldpassword == "" {
		return errors.New("什么都不填，要我修改什么呢？")
	}
	user, err := GetUserByMail(mail)
	if err != nil {
		return errors.New("我取不到你的信息呢！")
	}
	if newpassword != "" {
		if oldpassword == "" {
			return errors.New("旧的密码没有输入 ")
		}
		if CheckPassword(user.Password, oldpassword) {
			user.Password, err = HashPassword(newpassword)
			if err != nil {
				return errors.New("新的密码无法Hash ")
			}
		} else {
			return errors.New("旧的密码错误 ")
		}
	}

	if newname != "" {
		user.Name = strings.ReplaceAll(newname, " ", "")
	}
	sysinit.Db.Save(user)
	return nil
}

// 读数据库设置
func ReadSetting(name string) (string, error) {
	var setting Setting
	m := sysinit.Db.Where("name = ?", name).First(&setting)
	if m.Error != nil {
		return "", m.Error
	}
	return setting.Data, nil
}

// 写数据库设置
func WriteSetting(name, data string) error {
	var setting = Setting{
		Name: name,
		Data: data,
	}
	m := sysinit.Db.Save(setting)
	return m.Error
}
