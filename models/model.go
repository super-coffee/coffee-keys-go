package models

import (
	"coffee-keys-go/sysinit"
	"crypto/md5"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 用户表
type User struct {
	Id       int      `gorm:"primary_key" json:"id"`
	Name     string   `gorm:"unique;VARCHAR(191)" json:"name"`
	Mail     string   `gorm:"unique;VARCHAR(191)" json:"mail"`
	Password string   `gorm:"not null VARCHAR(191)" json:"password"`
	Date     JSONTime `json:"date"`
	Regip    string   `gorm:"unique;VARCHAR(191)" json:"regip"`
	Recip    string   `gorm:"unique;VARCHAR(191)" json:"recip"`
	Role     int      `json:"role"`
}

// 密匙表
type Pubkey struct {
	Id          int      `gorm:"primary_key" json:"id"`
	U_id        int      `json:"u_id"`
	Pubkey      string   `gorm:"unique;VARCHAR(191)" json:"pubkey"`
	Description string   `gorm:"unique;VARCHAR(191)" json:"description"`
	Date        JSONTime `json:"date"`
}

// 设置表
type Setting struct {
	Id   int    `gorm:"primary_key" json:"id"`
	Name string `gorm:"unique;VARCHAR(191)" json:"name"`
	Data string `gorm:"unique;VARCHAR(191)" json:"data"`
}

type JSONTime struct {
	time.Time
}

func (t JSONTime) String() string {
	return fmt.Sprintf("%s", t.Format("2006-01-02 15:04:05"))
}

func (t JSONTime) MarshalBinary() ([]byte, error) {
	formatted := fmt.Sprintf("\"%s\"", t.Format("2006-01-02 15:04:05"))
	return []byte(formatted), nil
}

// MarshalJSON on JSONTime format Time field with %Y-%m-%d %H:%M:%S
func (t JSONTime) MarshalJSON() ([]byte, error) {
	formatted := fmt.Sprintf("\"%s\"", t.Format("2006-01-02 15:04:05"))
	return []byte(formatted), nil
}

func (t JSONTime) MarshalText() ([]byte, error) {
	formatted := fmt.Sprintf("\"%s\"", t.Format("2006-01-02 15:04:05"))
	return []byte(formatted), nil
}

// Value insert timestamp into mysql need this function.
func (t JSONTime) Value() (driver.Value, error) {
	var zeroTime time.Time
	if t.Time.UnixNano() == zeroTime.UnixNano() {
		return nil, nil
	}
	return t.Time, nil
}

// Scan valueof time.Time
func (t *JSONTime) Scan(v interface{}) error {
	value, ok := v.(time.Time)
	if ok {
		*t = JSONTime{Time: value}
		return nil
	}
	return fmt.Errorf("can not convert %v to timestamp", v)
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

// 通过用户的ID获取用户
func GetUserById(id int) (User, error) {
	var user User
	m := sysinit.Db.Where("id = ?", id).First(&user)
	if m.Error != nil {
		return User{}, m.Error
	}
	return user, nil
}

// 获取所有的用户 废弃
func GetAllUser() ([]User, error) {
	var users []User
	m := sysinit.Db.Find(&users)
	if m.Error != nil {
		return nil, m.Error
	}
	return users, nil
}

// 获取指定页数的用户
func GetPageUsers(page, pageSize int) ([]User, error) {
	var users []User
	u := sysinit.Db.Limit(pageSize).Offset((page - 1) * pageSize).Order("id asc").Find(&users)
	return users, u.Error
}

// 获取用户数目
func GetUserCount() (int, error) {
	var total int = 0
	u := sysinit.Db.Model(&User{}).Count(&total)
	return total, u.Error
}

// 通过邮箱获取密匙
func GetKeyByMail(mail string) ([]Pubkey, error) {
	var pubkeys []Pubkey
	user, err := GetUserByMail(mail)
	if err != nil {
		return nil, err
	}
	if user.Role == -1 {
		return nil, errors.New("用户已被封禁")
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
func VerifyPassword(mail, password, ip string) (User, error) {
	user, err := GetUserByMail(mail)
	if err != nil {
		return user, err
	} else {
		if CheckPassword(user.Password, password) {
			user.Recip = ip
			sysinit.Db.Save(&user)
			return user, nil
		} else {
			return User{}, errors.New("用户名密码不正确")
		}

	}
}

// 新建key
func CreateKey(u_id int, publickey, info string) error {
	key := Pubkey{
		Description: info,
		Date:        JSONTime{time.Now()},
		Pubkey:      publickey,
		U_id:        u_id,
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
func Register(name, mail, password, password2, ip string) error {
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
		Date:     JSONTime{time.Now()},
		Password: hashpassword,
		Name:     strings.ReplaceAll(name, " ", ""),
		Recip:    ip,
		Regip:    ip,
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
	err = sysinit.Db.Save(&user).Error
	return err
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
	var setting Setting
	m := sysinit.Db.Where("name = ?", name).First(&setting)
	if m.Error != nil {
		return m.Error
	}
	setting.Data = data
	return sysinit.Db.Save(&setting).Error
}

// 通过ID封禁用户
func BanUser(id int) error {
	user, err := GetUserById(id)
	if err != nil {
		return err
	}
	if user.Role == 1 {
		return errors.New("管理员账号禁止操作")
	}
	user.Role = -1
	return sysinit.Db.Save(&user).Error
}

// 通过ID解除封禁用户
func UnBanUser(id int) error {
	user, err := GetUserById(id)
	if err != nil {
		return err
	}
	if user.Role == 1 {
		return errors.New("管理员账号禁止操作")
	}
	user.Role = 0
	return sysinit.Db.Save(&user).Error
}

// 通过ID删除用户
func RemoveUser(id int) error {
	user, err := GetUserById(id)
	if err != nil {
		return err
	}
	if user.Role == 1 {
		return errors.New("管理员账号禁止操作")
	}
	err = sysinit.Db.Where("u_id=?", user.Id).Delete(&Pubkey{}).Error
	if err != nil {
		return err
	}
	return sysinit.Db.Delete(&user).Error
}

// 通过ID重置用户密码
func ResetPasswordById(id int) (string, error) {
	user, err := GetUserById(id)
	if err != nil {
		return "", err
	}
	if user.Role == 1 {
		return "", errors.New("管理员账号禁止操作")
	}
	salt := int(time.Now().Unix())
	newPassword := md5V(strconv.Itoa(salt + rand.Intn(100)))
	newHashPassword, err := HashPassword(newPassword)
	if err != nil {
		return "", err
	}
	user.Password = newHashPassword
	err = sysinit.Db.Save(&user).Error
	if err != nil {
		return "", err
	}

	return newPassword, nil
}

func md5V(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}
