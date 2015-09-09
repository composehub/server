package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/codegangsta/negroni"
	"github.com/dustin/go-humanize"
	"github.com/extemporalgenome/slug"
	gr "github.com/ftrvxmtrx/gravatar"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	"github.com/julienschmidt/httprouter"
	"github.com/mholt/binding"
	"github.com/sendgrid/sendgrid-go"
	"github.com/unrolled/render"
	"golang.org/x/crypto/bcrypt"
)

type Vars struct {
	Packages []Package
	Package  Package
	User     User
	Q        string
	Length   int
}

type User struct {
	Id                int64  `json:"id"`
	EncryptedPassword string `json:"-" sql:"type:varchar(255);"`
	Password          string `json:"password" sql:"-" sql:"type:varchar(255);"`
	Name              string `json:"name" sql:"-" sql:"type:varchar(255);"`
	Handle            string `json:"handle" sql:"type:varchar(55);"`
	Email             string `json:"email" sql:"type:varchar(255);"`
	PasswordToken     string `json:"-" sql:"type:varchar(255);"`
	Packages          []Package
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletedAt         *time.Time `json:"-"`
}

type Package struct {
	Id             int64  `json:"id"`
	Name           string `json:"name" sql:"type:varchar(255);"`
	Email          string `json:"email" sql:"type:varchar(255);"`
	Tags           string `json:"tags" sql:"type:varchar(255);"`
	Blurb          string `json:"blurb" sql:"type:varchar(200)"`
	Description    string `json:"description" sql:"type:TEXT;"`
	RepoUrl        string `json:"repo_url" sql:"type:varchar(2083);"`
	Commit         string `json:"commit" sql:"type:varchar(255);"`
	Private        bool   `json:"private"`
	User           User
	UserId         int64 `json:"user_id"`
	TotalDownloads int64 `json:"total_downloads"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      *time.Time `json:"-"`
}

type Download struct {
	Id        int64 `json:"id"`
	PackageId int64 `json:"package_id"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time `json:"-"`
}

func (user *User) FieldMap() binding.FieldMap {
	return binding.FieldMap{
		&user.Email: binding.Field{
			Form:     "Email",
			Required: true,
		},
		&user.Password: binding.Field{
			Form:     "Password",
			Required: true,
		},
	}
}

func requireAuth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Basic realm=\"Authorization Required\"")
	http.Error(w, "Not Authorized", http.StatusUnauthorized)
}

func authUser(email, password string) (User, error) {
	//check user in db
	var user User
	if err := DB.Model(User{}).Where(&User{Email: email}).First(&user).Error; err == nil {
	} else {
		devlog(err)
	}
	err := bcrypt.CompareHashAndPassword([]byte(user.EncryptedPassword), []byte(password))
	if err == nil {
		//fmt.Println("success check user", user)
	}
	return user, err
}

func checkUser(email string) (int8, error) {
	//check user in db
	var count int8
	var err error
	if err = DB.Model(User{}).Where(&User{Email: email}).Count(&count).Error; err == nil {
		//fmt.Println("success check user", count)
	} else {
		//devlog(err)
	}
	return count, err
}

var (
	DB                                 gorm.DB
	R                                  *render.Render
	DbUser, DbPass, DbURL, DbName, Dev string
)
var T = make(map[string]*template.Template)

func init() {
	Dev = os.Getenv("DEV")
	funcs := template.FuncMap{
		"inc":      inc,
		"split":    split,
		"gravatar": gravatar,
		"timeAgo":  timeAgo,
	}
	T["index.html"], _ = template.New("base.html").Funcs(funcs).ParseFiles("assets/index.html", "assets/base.html")
	T["search.html"], _ = template.New("base.html").Funcs(funcs).ParseFiles("assets/search.html", "assets/base.html")
	T["package.html"], _ = template.New("base.html").Funcs(funcs).ParseFiles("assets/package.html", "assets/base.html")
	T["user.html"], _ = template.New("base.html").Funcs(funcs).ParseFiles("assets/user.html", "assets/base.html")

	//T["package.html"] = template.Must(template.ParseFiles("assets/package.html", "assets/base.html"))
	//T["user.html"] = template.Must(template.ParseFiles("assets/user.html", "assets/base.html"))
	//T["user.html"] = setFuncs(T["user.html"])
	//T["package.html"] = setFuncs(T["package.html"])

	DbUser = os.Getenv("")
	DbPass = os.Getenv("COMPOSITOR_DB_1_ENV_MYSQL_ROOT_PASSWORD")
	DbURL = os.Getenv("COMPOSITOR_DB_1_PORT_3306_TCP_ADDR")
	DbName = os.Getenv("COMPOSITOR_DB_1_ENV_MYSQL_DATABASE")
	if DbUser == "" {
		DbUser = "root"
	}
	if DbPass == "" {
		DbPass = "root"
	}
	if DbName == "" {
		DbName = "composehub"
	}
	if DbURL == "" {
		DbURL = "localhost"
	}
	db, err := gorm.Open("mysql", DbUser+":"+DbPass+"@tcp("+DbURL+":3306)/?charset=utf8mb4&parseTime=True&loc=Local")
	if err != nil {
		devlog(DbUser + ":" + DbPass + "@" + DbURL + "/" + DbName + "?charset=utf8mb4&parseTime=True&loc=Local")
		log.Fatalln(err)
	}
	db.Exec("CREATE DATABASE if not exists `" + DbName + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci")
	err = db.Exec("USE " + DbName).Error
	if err != nil {
		panic(err)
	}
	db.DB()
	DB = db
	if Dev != "" {
		DB.LogMode(true)
	}

	DB.AutoMigrate(&User{})
	DB.AutoMigrate(&Package{})
	DB.AutoMigrate(&Download{})
	DB.Exec("alter table packages add unique index(name);")
	DB.Exec("alter table users add unique index(email);")
	DB.Exec("alter table users add unique index(handle);")
	R = render.New(render.Options{})
}

func main() {
	devlog("lol")
	router := httprouter.New()
	router.POST("/publish/:name", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		r.ParseForm()
		defer r.Body.Close()
		b, _ := ioutil.ReadAll(r.Body)
		devlog(string(b))
		postedpkg := Package{}
		if err := json.Unmarshal(b, &postedpkg); err != nil {
			devlog(string(b), err)
			message := "Sorry, something wrong happened"
			R.JSON(w, http.StatusInternalServerError, map[string]string{"message": message})
			return
		}
		u, p, ok := r.BasicAuth()
		if ok && p == "" {
			requireAuth(w)
		} else {
			if user, err := authUser(u, p); err != nil {
				requireAuth(w)
			} else {
				devlog("FOUND", user.Id, postedpkg.Name)
				pkg := Package{}
				if err := DB.Where(&Package{UserId: user.Id, Name: ps.ByName("name")}).First(&pkg).Error; err != nil &&
					err != gorm.RecordNotFound {
					R.JSON(w, http.StatusNotFound, "xpackage "+postedpkg.Name+" not found")
					return
				} else {
					pkg.UserId = user.Id
					pkg.Private = postedpkg.Private
					if postedpkg.Name != "" {
						pkg.Name = slug.Slug(postedpkg.Name)
					}
					pkg.Tags = postedpkg.Tags
					if postedpkg.Email != "" {
						pkg.Email = postedpkg.Email
					}
					if postedpkg.Blurb != "" {
						pkg.Blurb = postedpkg.Blurb
					}
					if postedpkg.Description != "" {
						pkg.Description = postedpkg.Description
					}
					if postedpkg.RepoUrl != "" {
						pkg.RepoUrl = postedpkg.RepoUrl
					}

					if pkg.Name == "" {
						message := "Sorry, you need to specify a name for your package."
						R.JSON(w, http.StatusBadRequest, message)
						return
					}

					if pkg.RepoUrl == "" {
						message := "Sorry, you need to specify a git repo url for your package."
						R.JSON(w, http.StatusBadRequest, message)
						return
					}

					if err := DB.Save(&pkg).Error; err != nil {
						if strings.Contains(err.Error(), "Duplicate") {
							switch {
							case strings.Contains(err.Error(), "name"):
								devlog(pkg.Id, pkg)
								message := "sorry, a package with the same name " + pkg.Name + " already exists."
								R.JSON(w, http.StatusBadRequest, message)
								return
							}

							devlog(err, pkg.Id, pkg.Name, pkg)
							R.JSON(w, http.StatusNotFound, "package "+pkg.Name+" not found")
							return
						}
					} else {
						devlog("ok, package published!", pkg)
						R.JSON(w, http.StatusOK, pkg)
						return
					}

				}
			}
		}
	})
	router.POST("/packages", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		r.ParseForm()
		u, p, ok := r.BasicAuth()
		if ok && p == "" {
			requireAuth(w)
		} else {
			if user, err := authUser(u, p); err != nil {
				requireAuth(w)
			} else {
				newPackage := Package{
					Name:  r.Form.Get("name"),
					Email: r.Form.Get("email"),
					//Tags:        r.Form.Get("tags"),
					Blurb:       r.Form.Get("blurb"),
					Description: r.Form.Get("description"),
					RepoUrl:     r.Form.Get("repo_url"),
					Commit:      r.Form.Get("commit"),
					UserId:      user.Id,
				}
				newPackage.Name = slug.Slug(newPackage.Name)
				if err := DB.Save(&newPackage).Error; err == nil {
					R.JSON(w, http.StatusOK, newPackage)
					return
				} else {
					R.JSON(w, http.StatusBadRequest, "a package with the same name already exists")
					return
				}

			}
		}
	})
	router.POST("/users", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		newUser := User{}

		r.ParseForm()
		newUser.Email = r.Form.Get("email")
		newUser.Password = r.Form.Get("password")
		newUser.Handle = r.Form.Get("handle")
		if newUser.Email != "" && newUser.Password != "" && newUser.Handle != "" {
			if count, err := checkUser(newUser.Email); err != nil || count > 0 {
				R.JSON(w, http.StatusBadRequest, map[string]string{"message": "user with this email already exists"})
				return
			}

			ep, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), 10)
			if err != nil {
				devlog(err)
				R.JSON(w, http.StatusInternalServerError, err)
				return
			}
			newUser.EncryptedPassword = string(ep)
			err = DB.Save(&newUser).Error
			if err != nil {
				// Handle error
				message := "Sorry, something wrong happened"
				if strings.Contains(err.Error(), "Duplicate") {
					switch {
					case strings.Contains(err.Error(), "'handle'"):
						message = "sorry, a user with the same handle " + newUser.Handle + " already exists."
					case strings.Contains(err.Error(), "'email'"):
						message = "sorry, a user with the same email " + newUser.Email + " already exists."
					}
				}
				R.JSON(w, http.StatusInternalServerError, map[string]string{"message": message})
				fmt.Println(err)
				return
			}
			R.JSON(w, http.StatusOK, newUser)
			return
		} else {
			R.JSON(w, http.StatusBadRequest, map[string]string{"message": "email or password missing"})
			return
		}
	})

	router.PUT("/users/:email", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		r.ParseForm()
		defer r.Body.Close()
		b, _ := ioutil.ReadAll(r.Body)
		postedUser := User{}
		if err := json.Unmarshal(b, &postedUser); err != nil {
			message := "Sorry, something wrong happened"
			R.JSON(w, http.StatusInternalServerError, map[string]string{"message": message})
			return
		}
		email := postedUser.Email
		password := postedUser.Password
		handle := postedUser.Handle
		u, p, ok := r.BasicAuth()
		if ok && p == "" {
			requireAuth(w)
		} else {
			if user, err := authUser(u, p); err != nil {
				requireAuth(w)
			} else {
				if email != "" {
					user.Email = email
				}
				if handle != "" {
					user.Handle = handle
				}
				if password != "" {
					ep, err := bcrypt.GenerateFromPassword([]byte(password), 10)
					if err != nil {
						devlog(err)
						R.JSON(w, http.StatusInternalServerError, err)
						return
					}
					user.EncryptedPassword = string(ep)
				}
				if err := DB.Save(&user).Error; err == nil {
					R.JSON(w, http.StatusOK, user)
					return
				} else {
					devlog(err.Error())
					message := "sorry, something went wrong, we're looking into it."
					if strings.Contains(err.Error(), "Duplicate") {
						switch {
						case strings.Contains(err.Error(), "'handle'"):
							message = "sorry, a user with the same handle " + handle + " already exists."
						case strings.Contains(err.Error(), "'email'"):
							message = "sorry, a user with the same email " + email + " already exists."
						}
					}
					R.JSON(w, http.StatusBadRequest, map[string]string{"message": message})
					return
				}
			}
		}
	})

	router.GET("/search/:q", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		packages := []Package{}
		q := "%" + ps.ByName("q") + "%"
		if err := DB.Model(Package{}).Preload("User").Order("total_downloads desc").
			Where("private = 0 and (name like ? or description like ? or blurb like ?)", q, q, q).Find(&packages).Error; err != nil {
			R.JSON(w, http.StatusBadRequest, "[]")
			return
		}
		R.JSON(w, http.StatusOK, packages)
		return

	})

	router.GET("/hsearch", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		vars := Vars{}
		r.ParseForm()
		q := r.Form.Get("q")
		vars.Q = q
		q = "%" + q + "%"

		if err := DB.Model(Package{}).Preload("User").Select("packages.*, users.handle").
			Joins("left join users on users.id = packages.user_id").
			Order("total_downloads desc").Where("private = 0 and (name like ? or description like ? or tags like ?)", q, q, q).
			Find(&vars.Packages).Error; err != nil {
			devlog(err)
		}
		vars.Length = len(vars.Packages)
		T["search.html"].ExecuteTemplate(w, "base", vars)

		//html, err := readAsset(vars, path)
		//if err == nil {
		//w.Header().Set("Content-Type", "text/html")
		//w.Write([]byte(html))
		//} else {
		//return
		//}
	})

	router.GET("/~:handle", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		handle := ps.ByName("handle")
		vars := Vars{}
		if err := DB.Where(User{Handle: handle}).First(&vars.User).Error; err != nil {
			R.JSON(w, http.StatusNotFound, "User not found.")
			return
		}
		if err := DB.Where("user_id = ? and private = ?", vars.User.Id, 0).Find(&vars.Packages).Error; err != nil {
			devlog(err)
		}
		vars.Length = len(vars.Packages)
		T["user.html"].ExecuteTemplate(w, "base", vars)

		//html, err := readAsset(vars, path)
		//if err == nil {
		//w.Header().Set("Content-Type", "text/html")
		//w.Write([]byte(html))
		//} else {
		//return
		//}

	})

	router.GET("/packages/:name", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		name := ps.ByName("name")
		pkg := Package{}
		if err := DB.Where(Package{Name: name}).First(&pkg).Error; err != nil {
			R.JSON(w, http.StatusBadRequest, "{}")
			return
		}
		if pkg.Private {
			u, p, ok := r.BasicAuth()
			if ok && p == "" {
				requireAuth(w)
				return
			} else {
				if user, err := authUser(u, p); err != nil {
					requireAuth(w)
					return
				} else {
					if user.Id != pkg.UserId {
						requireAuth(w)
						return
					}
				}

			}
		}
		if err := DB.Exec("update packages set total_downloads = total_downloads + 1 where name = ?", name).Error; err != nil {
			devlog(err)
		}
		var dl = Download{PackageId: pkg.Id}
		if err := DB.Save(&dl).Error; err != nil {
			devlog(err)
		}

		R.JSON(w, http.StatusOK, pkg)
		return

	})

	router.PUT("/users/:email/reset-password/:token", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		r.ParseForm()
		defer r.Body.Close()
		b, _ := ioutil.ReadAll(r.Body)
		user := User{}
		if err := json.Unmarshal(b, &user); err != nil {
			devlog(err)
			message := "Sorry, something wrong happened, we're looking into it."
			R.JSON(w, http.StatusBadRequest, map[string]string{"message": message})
			return
		}

		password := user.Password
		email := ps.ByName("email")
		token := ps.ByName("token")
		user = User{}
		if password == "" || token == "" {
			message := "Sorry, password can't be blank."
			R.JSON(w, http.StatusBadRequest, map[string]string{"message": message})
			return
		}

		if err := DB.Where(User{Email: email, PasswordToken: token}).First(&user).Error; err != nil {
			message := "Incorrect token, please reset your password again."
			R.JSON(w, http.StatusNotFound, map[string]string{"message": message})
			return
		}

		user.Password = password
		ep, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
		if err != nil {
			devlog(err)
			R.JSON(w, http.StatusInternalServerError, err)
			return
		}
		user.EncryptedPassword = string(ep)
		DB.Save(&user)
		if err != nil {
			// Handle error
			message := "Sorry, user could not be saved, we're looking into it."
			R.JSON(w, http.StatusInternalServerError, message)
			fmt.Println(err)
			return
		}
		R.JSON(w, http.StatusOK, user)

	})

	router.POST("/users/:email/reset-password", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		user := User{}
		if err := DB.Where(User{Email: ps.ByName("email")}).First(&user).Error; err != nil {
			message := "Please check your email!"
			devlog(err, ps.ByName("email"))
			R.JSON(w, http.StatusOK, map[string]string{"message": message})
			return
		}
		uuid, err := newUUID()
		if err != nil {
			message := "Sorry, something went wrong, we're looking into it."
			R.JSON(w, http.StatusInternalServerError, map[string]string{"message": message})
			return
		}
		user.PasswordToken = uuid
		if err := DB.Save(&user).Error; err != nil {
			message := "Sorry, something went wrong, we're looking into it."
			R.JSON(w, http.StatusInternalServerError, map[string]string{"message": message})
			return
		}
		sgu := os.Getenv("SG_USER")
		sgp := os.Getenv("SG_PASS")
		devlog(sgu, sgp)
		sg := sendgrid.NewSendGridClient(sgu, sgp)
		message := sendgrid.NewMail()
		message.AddTo(user.Email)
		message.AddToName(user.Name)
		message.SetSubject("Password reset")
		message.SetText("Use this code to reset your password " + user.PasswordToken)
		message.SetFrom("password@composehub.com")
		if r := sg.Send(message); r == nil {
			message := "Please check your email!"
			R.JSON(w, http.StatusOK, map[string]string{"message": message})
			return
		} else {
			message := "Sorry, something went wrong, we're looking into it."
			R.JSON(w, http.StatusInternalServerError, map[string]string{"message": message})
			return
		}
	})

	router.GET("/package/:name", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		vars := Vars{}
		name := ps.ByName("name")

		if err := DB.Model(Package{}).Where(Package{Name: name}).First(&vars.Package).Error; err != nil {
			devlog("err:", err)
			message := "Sorry, something went wrong, we're looking into it."
			R.JSON(w, http.StatusInternalServerError, map[string]string{"message": message})
			return
		}
		if err := DB.Model(User{}).Where(User{Id: vars.Package.UserId}).Find(&vars.User).Error; err != nil {
			devlog(err)
			message := "Sorry, something went wrong, we're looking into it."
			R.JSON(w, http.StatusInternalServerError, map[string]string{"message": message})
			return
		}
		T["package.html"].ExecuteTemplate(w, "base", vars)

		//if err == nil {
		//w.Header().Set("Content-Type", "text/html")
		//w.Write([]byte(html))
		//} else {
		//return
		//}

	})
	router.GET("/main.css", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		path := "assets/main.css"
		data, err := ioutil.ReadFile(path)

		if err != nil {
			devlog("Asset not found on path: " + path)
		} else {
			w.Header().Set("Content-Type", "text/css")
			w.Write(data)

		}

	})

	router.GET("/checkupdate/:version", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		latest := "0.2"
		if p.ByName("version") == latest {
			R.JSON(w, http.StatusOK, "ok")
		} else {
			R.JSON(w, http.StatusOK, latest)
		}
	})
	router.GET("/", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		vars := Vars{}
		//var path string
		//path = "assets/index.html"
		if err := DB.Where("private = ?", 0).Limit(10).Order("total_downloads desc").Find(&vars.Packages).Error; err != nil {
			devlog(err)
			message := "Sorry, something went wrong, we're looking into it."
			R.JSON(w, http.StatusInternalServerError, map[string]string{"message": message})
			return
		}
		T["index.html"].ExecuteTemplate(w, "base", vars)
		//devlog("Asset: ", string(data))
		//html, err := readAsset(vars, path)
		//if err == nil {
		//w.Header().Set("Content-Type", "text/html")
		//w.Write([]byte(html))
		//} else {
		//return
		//}

	})

	n := negroni.Classic()
	//n.Use(auth.Basic("username", "secretpassword"))
	n.UseHandler(router)
	n.Run(":3000")
}

func readAsset(vars Vars, path string) (string, error) {
	//_, err := ioutil.ReadFile(path)

	//if err != nil {
	//devlog("Asset not found on path: " + path)
	//return "", err
	//}
	//ti, errT := t.Parse(string(data))
	//if errT != nil {
	//devlog("Parse fail", errT)
	//return "", err
	//}

	//err = ti.Execute(&doc, vars)
	//if err != nil {
	//devlog("fail executing", err)
	//return "", err
	//// Asset was not found.
	//}
	//html := doc.String()
	return "", nil

}

func setFuncs(t *template.Template) *template.Template {
	t.Funcs(template.FuncMap{
		"inc":      inc,
		"split":    split,
		"gravatar": gravatar,
		"timeAgo":  timeAgo,
	})
	return t
}

func newUUID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

func inc(x int) int {
	return x + 1
}

func split(s string) []string {
	tags := strings.Split(s, ",")
	return tags

}

func gravatar(e, s string) string {
	emailHash := gr.EmailHash(e)
	url := "https://www.gravatar.com/avatar/" + emailHash + "?default=retro&amp;s=" + s
	return url
}

func timeAgo(t time.Time) string {
	return humanize.Time(t)
}

func devlog(v ...interface{}) {
	fmt.Println("Dev:", Dev)
	if Dev != "" {
		log.Println(v)
	}
}
