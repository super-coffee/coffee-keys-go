package main

import (
	conf "coffee-keys-go/config"
	"coffee-keys-go/models"
	"coffee-keys-go/sysinit"
	"context"
	"fmt"
	"github.com/iris-contrib/middleware/csrf"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/core/netutil"
	"github.com/kataras/iris/v12/middleware/logger"
	"github.com/kataras/iris/v12/middleware/recaptcha"
	"github.com/kataras/iris/v12/middleware/recover"
	"github.com/kataras/iris/v12/mvc"
	"github.com/kataras/iris/v12/sessions"
	"html"
	"regexp"
	"strconv"
	"time"
)

var (
	sess       = sessions.New(sessions.Config{Cookie: "sk"})
	protectUrl = []string{
		"^/admin",
	}
	adminUrl = []string{
		"^/admin/cf",
	}
	Client = netutil.Client(time.Duration(20 * time.Second))
)

func main() {
	fmt.Println("AUTHOR: ENJOY - QQ 2435932516 - Super-Coffee © 2020 - GPL3.0")
	app := iris.New()
	app.Use(recover.New(), logger.New())
	app.UseGlobal(before)
	protect := csrf.Protect([]byte(conf.Sysconfig.CsrfKey), csrf.Secure(false), csrf.ErrorHandler(csrfError))
	user := mvc.New(app.Party("/", protect))
	user.Handle(new(RootController))
	temple := iris.Django("./templates", ".html")
	temple.Reload(conf.Sysconfig.Debug)
	app.RegisterView(temple)
	app.OnErrorCode(iris.StatusNotFound, notFound)
	app.HandleDir("/static", "static")
	iris.RegisterOnInterrupt(func() {
		timeout := 10 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		// close all hosts
		app.Logger().Println("服务器正在关闭")
		err := sysinit.Db.Close()
		if err != nil {
			fmt.Println("数据库断开连接失败")
			fmt.Println(err.Error())
		} else {
			fmt.Println("数据库断开成功")
		}

		_ = app.Shutdown(ctx)

	})
	_ = app.Listen(":"+conf.Sysconfig.Port, iris.WithoutInterruptHandler)
	// _ = app.Run(iris.Addr(":"+conf.Sysconfig.Port), iris.WithoutServerError(iris.ErrServerClosed))
}
func before(ctx iris.Context) {
	protect := false
	for i := range protectUrl {
		match, _ := regexp.MatchString(protectUrl[i], ctx.Path())
		if match {
			protect = true
			break
		}
	}
	if protect {
		session := sess.Start(ctx)
		if session.Get("name") == nil {
			ctx.ViewData("code", "401 Error")
			ctx.ViewData("error", `您需要先<a href="/login">登录</a>才能访问！`)
			ctx.StatusCode(401)
			ctx.View("error.html")
			return
		}
	}
	adminProtect := false
	for i := range adminUrl {
		match, _ := regexp.MatchString(adminUrl[i], ctx.Path())
		if match {
			adminProtect = true
			break
		}
	}
	if adminProtect {
		session := sess.Start(ctx)
		if session.Get("role") != 1 {
			ctx.ViewData("code", "401 Error")
			ctx.ViewData("error", `您的用户权限不够<a href="/admin">首页</a>`)
			ctx.StatusCode(401)
			ctx.View("error.html")
			return
		}
	}
	ctx.Next()
}
func csrfError(ctx iris.Context) {
	ctx.ViewData("code", "403 CSRF Error")
	ctx.ViewData("error", "请不要非法攻击！")
	ctx.StatusCode(403)
	ctx.View("error.html")
}
func notFound(ctx iris.Context) {

	ctx.ViewData("code", "404 Not Found")
	ctx.ViewData("error", "有些东西似乎已经被黑洞吸走了呢！")
	ctx.View("error.html")
}

type RootController struct {
	Ctx iris.Context
}

func (c *RootController) Get() mvc.Result {

	return mvc.View{
		Name: "search.html",
		Data: iris.Map{"key": csrf.Token(c.Ctx)},
	}
}
func (c *RootController) GetLogin() mvc.Result {
	session := sess.Start(c.Ctx)
	//// Debug
	//session.Set("name", "enjoy")
	//session.Set("role", 0)
	//session.Set("mail", "enjoy@mcoo.pw")
	//// EndDebug
	if session.Get("name") != nil {
		return mvc.Response{Path: "/admin"}
	}

	return mvc.View{
		Name: "login.html",
		Code: 200,
		Data: iris.Map{"key": csrf.Token(c.Ctx), "google": showRecaptchaForm()},
	}
}
func (c *RootController) GetRegister() mvc.Result {
	session := sess.Start(c.Ctx)
	if session.Get("name") != nil {
		return mvc.Response{Path: "/admin"}
	}

	return mvc.View{
		Name: "register.html",
		Code: 200,
		Data: iris.Map{"key": csrf.Token(c.Ctx), "google": showRecaptchaForm()},
	}
}

func (c *RootController) PostApiSearchkey() iris.Map {
	pubkeys, err := models.GetKeyByMail(c.Ctx.FormValue("mail"))
	if err != nil {
		if conf.Sysconfig.Debug == true {
			return iris.Map{"status": false, "data": err.Error()}
		}
		return iris.Map{"status": false, "data": "未找到相关密匙"}
	}
	return iris.Map{"status": true, "data": pubkeys}
}
func showRecaptchaForm() string {
	var htmlForm = `
<div class="form-group">
<div class="g-recaptcha" data-sitekey="%s"></div></div>
<script src="https://www.recaptcha.net/recaptcha/api.js"></script>
`
	return fmt.Sprintf(htmlForm, conf.Sysconfig.RecaptchaPublic)
}
func (c *RootController) GetApiVerifyauth() iris.Map {
	session := sess.Start(c.Ctx)
	if session.Get("name") != nil {
		return iris.Map{"status": true, "data": session.Get("name")}
	} else {
		return iris.Map{"status": false, "data": "尚未登录"}
	}

}
func (c *RootController) PostApiRegister() iris.Map {
	result := recaptcha.SiteFerify(c.Ctx, conf.Sysconfig.RecaptchaSecret)
	if !result.Success {
		return iris.Map{"status": false, "data": "请进行行为验证!"}
	}
	mail := c.Ctx.FormValue("mail")
	err := models.Register(c.Ctx.FormValue("name"), mail, c.Ctx.FormValue("password"), c.Ctx.FormValue("repeat-password"), c.Ctx.RemoteAddr())
	if err != nil {
		return iris.Map{"status": false, "data": err.Error()}
	}
	user, err := models.GetUserByMail(mail)
	if err != nil {
		return iris.Map{"status": false, "data": "注册失败，原因未知!"}
	}
	session := sess.Start(c.Ctx)
	session.Set("name", user.Name)
	session.Set("role", user.Role)
	session.Set("mail", user.Mail)
	return iris.Map{"status": true, "data": user.Name}
}
func (c *RootController) PostApiVerifypassword() iris.Map {

	result := recaptcha.SiteFerify(c.Ctx, conf.Sysconfig.RecaptchaSecret)
	if !result.Success {
		return iris.Map{"status": false, "data": "请进行行为验证!"}
	}
	user, err := models.VerifyPassword(c.Ctx.FormValue("mail"), c.Ctx.FormValue("password"), c.Ctx.RemoteAddr())
	if err != nil {
		if conf.Sysconfig.Debug {
			return iris.Map{"status": false, "data": err.Error()}
		}
		return iris.Map{"status": false, "data": "邮箱或密码错误"}
	}
	if user.Role == -1 {
		return iris.Map{"status": false, "data": "用户已被封禁"}
	}
	session := sess.Start(c.Ctx)
	session.Set("name", user.Name)
	session.Set("role", user.Role)
	session.Set("uid", user.Id)
	session.Set("mail", user.Mail)
	return iris.Map{"status": true, "data": user.Name}
}
func (c *RootController) GetAdmin() mvc.Result {
	session := sess.Start(c.Ctx)
	keys, err := models.GetKeyByMail(session.GetString("mail"))
	if err != nil {
		keys = nil
	}
	notice, err := models.ReadSetting("notice")
	if err != nil {
		notice = ""
	}
	return mvc.View{
		Name: "home.html",
		Data: iris.Map{"uid": session.Get("uid"), "csrf": csrf.TemplateField(c.Ctx), "notice": notice, "name": session.Get("name"), "mail": session.Get("mail"), "keys": keys, "role": session.Get("role"), "key": csrf.Token(c.Ctx)},
	}
}
func (c *RootController) GetAdminUser() mvc.Result {
	session := sess.Start(c.Ctx)
	keys, err := models.GetKeyByMail(session.GetString("mail"))
	if err != nil {
		keys = nil
	}
	return mvc.View{
		Name: "user.html",
		Data: iris.Map{"csrf": csrf.TemplateField(c.Ctx), "name": session.Get("name"), "mail": session.Get("mail"), "keys": keys, "role": session.Get("role"), "key": csrf.Token(c.Ctx)},
	}
}
func (c *RootController) GetAdminDelBy(id int) mvc.Response {
	session := sess.Start(c.Ctx)
	mail := session.GetString("mail")
	_, err := models.DelKeyByIdSafe(id, mail)
	if err != nil {
		return mvc.Response{
			Path: "/admin",
		}
	}
	return mvc.Response{
		Path: "/admin",
	}
}
func (c *RootController) GetAdminKeyBy(id int) iris.Map {
	pubkey, err := models.GetKeyById(id)
	if err != nil {
		return iris.Map{
			"status": false,
			"data":   "找不到key",
		}
	}
	return iris.Map{
		"status": true,
		"data":   pubkey.Pubkey,
	}
}
func (c *RootController) PostAdminAdd() mvc.Response {
	session := sess.Start(c.Ctx)
	user, err := models.GetUserByMail(session.GetString("mail"))
	if err != nil {
		return mvc.Response{
			Path: "/admin",
		}
	}
	info := c.Ctx.FormValue("info")
	key := c.Ctx.FormValue("content")
	if key == "" || info == "" {
		return mvc.Response{
			Path: "/admin",
		}
	}
	err = models.CreateKey(user.Id, key, info)
	if err != nil {
		return mvc.Response{
			Path: "/admin",
		}
	}
	return mvc.Response{
		Path: "/admin",
	}
}
func (c *RootController) GetAdminLogout() mvc.Result {
	session := sess.Start(c.Ctx)
	session.Clear()
	return mvc.Response{
		Path: "/login",
	}
}
func (c *RootController) PostAdminEditUser() iris.Map {
	session := sess.Start(c.Ctx)
	fmt.Println(c.Ctx.FormValue("oldpassword"))
	err := models.EditUser(session.GetString("mail"), c.Ctx.FormValue("oldpassword"), c.Ctx.FormValue("newname"), c.Ctx.FormValue("newpassword"))
	if err != nil {
		return iris.Map{
			"status": false,
			"data":   err.Error(),
		}
	}
	user, _ := models.GetUserByMail(session.GetString("mail"))
	session.Set("name", user.Name)
	session.Set("role", user.Role)
	session.Set("uid", user.Id)
	session.Set("mail", user.Mail)
	return iris.Map{
		"status": true,
		"data":   "修改成功",
	}
}
func (c *RootController) GetAdminCf() mvc.Result {
	session := sess.Start(c.Ctx)
	keys, err := models.GetKeyByMail(session.GetString("mail"))
	if err != nil {
		keys = nil
	}
	notice, err := models.ReadSetting("notice")
	if err != nil {
		notice = ""
	}

	return mvc.View{
		Name: "cf.html",
		Data: iris.Map{"uid": session.Get("uid"), "csrf": csrf.TemplateField(c.Ctx), "notice": notice, "name": session.Get("name"), "mail": session.Get("mail"), "keys": keys, "role": session.Get("role"), "key": csrf.Token(c.Ctx)},
	}
}
func (c *RootController) GetAdminCfUsersBy(fun, page, pagesize int) iris.Map {
	if fun == 0 {
		count, err := models.GetUserCount()
		if err != nil {
			return iris.Map{"status": false, "data": err.Error()}
		}
		return iris.Map{"status": true, "data": count}
	}
	users, err := models.GetPageUsers(page, pagesize)
	if err != nil {
		return iris.Map{"status": false, "data": err.Error()}
	}
	return iris.Map{"status": true, "data": users}

}
func (c *RootController) PostAdminCfUpset() iris.Map {
	err := models.WriteSetting("notice", html.UnescapeString(c.Ctx.FormValue("notice")))
	if err != nil {
		return iris.Map{"status": false, "data": err.Error()}
	}
	return iris.Map{"status": true, "data": "修改成功!"}
}
func (c *RootController) PostAdminCfBan() iris.Map {
	id, err := strconv.Atoi(c.Ctx.FormValueDefault("id", "-1"))
	if err != nil {
		return iris.Map{"status": false, "data": err.Error()}
	}
	err = models.BanUser(id)
	if err != nil {
		return iris.Map{"status": false, "data": err.Error()}
	}
	return iris.Map{"status": true, "data": "封禁成功"}
}
func (c *RootController) PostAdminCfUnban() iris.Map {
	id, err := strconv.Atoi(c.Ctx.FormValueDefault("id", "-1"))
	if err != nil {
		return iris.Map{"status": false, "data": err.Error()}
	}
	err = models.UnBanUser(id)
	if err != nil {
		return iris.Map{"status": false, "data": err.Error()}
	}
	return iris.Map{"status": true, "data": "解除封禁成功"}
}
func (c *RootController) PostAdminCfRemove() iris.Map {
	id, err := strconv.Atoi(c.Ctx.FormValueDefault("id", "-1"))
	if err != nil {
		return iris.Map{"status": false, "data": err.Error()}
	}
	err = models.RemoveUser(id)
	if err != nil {
		return iris.Map{"status": false, "data": err.Error()}
	}
	return iris.Map{"status": true, "data": "删除账号成功"}
}
func (c *RootController) PostAdminCfReset() iris.Map {
	id, err := strconv.Atoi(c.Ctx.FormValueDefault("id", "-1"))
	if err != nil {
		return iris.Map{"status": false, "data": err.Error()}
	}
	newPassword, err := models.ResetPasswordById(id)
	if err != nil {
		return iris.Map{"status": false, "data": err.Error()}
	}
	return iris.Map{"status": true, "data": newPassword}
}
