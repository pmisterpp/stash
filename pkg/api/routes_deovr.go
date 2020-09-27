package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stashapp/stash/pkg/deovr"
	"github.com/stashapp/stash/pkg/manager/config"
	"github.com/stashapp/stash/pkg/plugin/common/log"

	"github.com/go-chi/chi"
	"github.com/stashapp/stash/pkg/models"
)

type deovrRoutes struct{}

func (rs deovrRoutes) Routes() chi.Router {
	r := chi.NewRouter()

	//r.Use(DeoVRAuth)

	r.Get("/", rs.DeoVR)
	r.Post("/", rs.DeoVR)

	r.Route("/scene/{sceneId}", func(r chi.Router) {
		r.Use(SceneCtx)
		r.Get("/", rs.DeoVRScene)
		r.Post("/", rs.DeoVRScene)
	})

	return r
}

func (rs deovrRoutes) DeoVR(w http.ResponseWriter, r *http.Request) {
	qb := models.NewSceneQueryBuilder()
	tqb := models.NewTagQueryBuilder()
	tags := []string{}

	tag, err := tqb.FindByName("VR", nil, false)
	if err == nil && tag != nil {
		tags = append(tags, strconv.Itoa(tag.ID))
	}

	tag, err = tqb.FindByName("vr", nil, false)
	if err == nil && tag != nil {
		tags = append(tags, strconv.Itoa(tag.ID))
	}

	hasVRTag := models.MultiCriterionInput{
		Value:    tags,
		Modifier: models.CriterionModifierIncludes,
	}

	sceneFilterType := models.SceneFilterType{
		Tags: &hasVRTag,
	}

	scenes, _ := qb.Query(&sceneFilterType, nil)

	baseURL, _ := r.Context().Value(BaseURLCtxKey).(string)

	userID := r.Context().Value(ContextUser).(string)
	token, err := createToken(userID)
	if err != nil {
		http.Error(w, http.StatusText(503), 503)
		return
	}
	payload := deovr.LibraryToDeoVRJSON(baseURL, token, scenes)

	json, err := json.Marshal(payload)

	if err != nil {
		http.Error(w, http.StatusText(503), 503)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

// func DeoVRAuth(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		if r.Method == "POST" {

// 			// ignore error - we want a new session regardless
// 			newSession, _ := sessionStore.Get(r, cookieName)

// 			username := r.FormValue("login")
// 			password := r.FormValue("password")

// 			log.Debugf("DEOVR logging in %s %s", username, password)

// 			// authenticate the user
// 			if !config.ValidateCredentials(username, password) {
// 				WriteDeoVRUnauthorized(w)
// 				return
// 			}

// 			newSession.Values[userIDKey] = username

// 			err := newSession.Save(r, w)
// 			if err != nil {
// 				http.Error(w, err.Error(), http.StatusInternalServerError)
// 				return
// 			}

// 			r.Method = "GET"
// 		}

// 		next.ServeHTTP(w, r)
// 	})
// }

// func (rs deovrRoutes) DeoVRLogin(nextHandler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		// ignore error - we want a new session regardless
// 		newSession, _ := sessionStore.Get(r, cookieName)

// 		username := r.FormValue("login")
// 		password := r.FormValue("password")

// 		log.Debugf("DEOVR logging in %s %s", username, password)

// 		// authenticate the user
// 		if !config.ValidateCredentials(username, password) {
// 			WriteDeoVRUnauthorized(w)
// 			return
// 		}

// 		newSession.Values[userIDKey] = username

// 		err := newSession.Save(r, w)
// 		if err != nil {
// 			http.Error(w, err.Error(), http.StatusInternalServerError)
// 			return
// 		}

// 		// http.Redirect(w, r, url, http.StatusFound)
// 		nextHandler(w, r)
// 	}
// }

// WriteDeoVRUnauthorized Writes unauthorized to response
func WriteDeoVRUnauthorized(w http.ResponseWriter) {
	log.Debugf("Unauthorized")

	payload := map[string]interface{}{
		"scenes": []interface{}{
			map[string]interface{}{
				"name": "Login Required",
				"list": nil,
			},
		},
		"authorized": "-1",
	}

	json, _ := json.Marshal(payload)

	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

func (rs deovrRoutes) DeoVRScene(w http.ResponseWriter, r *http.Request) {
	scene := r.Context().Value(sceneKey).(*models.Scene)
	baseURL, _ := r.Context().Value(BaseURLCtxKey).(string)

	userID := r.Context().Value(ContextUser).(string)
	token, err := createToken(userID)
	if err != nil {
		http.Error(w, http.StatusText(503), 503)
		return
	}

	payload := deovr.ToDeoVRJSON(baseURL, token, scene)

	json, err := json.Marshal(payload)

	if err != nil {
		http.Error(w, http.StatusText(503), 503)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

func getDeoVRAuthUserID(w http.ResponseWriter, r *http.Request) (string, error) {
	if r.Method == "POST" {
		username := r.FormValue("login")
		password := r.FormValue("password")

		// authenticate the user
		if config.ValidateCredentials(username, password) {
			return username, nil
		}

		return "", nil
	}
	return vaildateToken(r.URL.Query().Get("token"))
}

func vaildateToken(tokenString string) (string, error) {
	if tokenString == "" {
		return "", nil
	}

	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return config.GetJWTSignKey(), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if int64(claims["exp"].(float64)) > time.Now().Unix() {
			return claims["userid"].(string), nil
		}
	}
	return "", err
}

func createToken(username string) (string, error) {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userid": username,
		"exp":    time.Now().Add(time.Hour * 2).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	return token.SignedString(config.GetJWTSignKey())
}
