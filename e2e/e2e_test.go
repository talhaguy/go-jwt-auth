package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/talhaguy/go-jwt-auth/handler"
	"github.com/talhaguy/go-jwt-auth/repository"
	"github.com/talhaguy/go-jwt-auth/route"
)

var protocol = "http"
var host = "127.0.0.1"
var port = "8888"
var fullHost = protocol + "://" + host + ":" + port

func startServer(started chan bool) {
	handlers := handler.NewDefaultRouteHandler(
		repository.NewInMemoryUserRepository(),
		repository.NewInMemoryBlacklistedRefreshTokenRepository(),
		"my-access-token-secret",
		"my-refresh-token-secret",
	)

	router, subRouter := route.SetupRoutes(
		handlers,
		[]string{"http://localhost:8000"},
	)

	subRouter.HandleFunc("/data", ApiDataHandler).Methods(http.MethodPost).Headers("Content-Type", "application/json")

	server := &http.Server{
		Handler:      router,
		Addr:         host + ":" + port,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	started <- true

	log.Fatal(server.ListenAndServe())
}

func ApiDataHandler(rw http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(rw, `{
		"status": "SUCCESS",
		"message": ""
	}`)
}

// TODO: add blacklisted token tests

func TestServer(t *testing.T) {
	s := make(chan bool)
	go startServer(s)

	// wait till server starts
	<-s

	t.Run("valid registration", func(t *testing.T) {
		// TODO: test invalid form
		form := handler.RegistrationForm{
			Username: "user@domain.com",
			Password: "asdfasdf",
		}
		body, err := json.Marshal(form)
		if err != nil {
			t.Fatal("error creating request body")
		}

		req, err := http.NewRequest(http.MethodPost, fullHost+"/register", bytes.NewBuffer(body))
		if err != nil {
			t.Fatalf("error creating request: %s", err.Error())
		}
		req.Header.Add("Content-Type", "application/json")

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("error in request")
		}

		responseBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal("error reading response body")
		}

		var serverResponse handler.ServerResponse
		err = json.Unmarshal(responseBody, &serverResponse)
		if err != nil {
			t.Fatal("error unmarshalling response")
		}

		if serverResponse.Status != "SUCCESS" {
			t.Fatal("expected SUCCESS")
		}
	})

	t.Run("non-existing user login", func(t *testing.T) {
		form := handler.LoginForm{
			Username: "i_dont_exist@domain.com",
			Password: "asdfasdf",
		}
		body, err := json.Marshal(form)
		if err != nil {
			t.Fatal("error creating request body")
		}

		req, err := http.NewRequest(http.MethodPost, fullHost+"/login", bytes.NewBuffer(body))
		if err != nil {
			t.Fatalf("error creating request: %s", err.Error())
		}
		req.Header.Add("Content-Type", "application/json")

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("error in request")
		}

		responseBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal("error reading response body")
		}

		var serverResponse handler.AccessTokenServerResponse
		err = json.Unmarshal(responseBody, &serverResponse)
		if err != nil {
			t.Fatal("error unmarshalling response")
		}

		if serverResponse.Status != "ERROR" {
			t.Fatal("expected ERROR")
		}
	})

	t.Run("wrong password user login", func(t *testing.T) {
		form := handler.LoginForm{
			Username: "user@domain.com",
			Password: "wrong_password",
		}
		body, err := json.Marshal(form)
		if err != nil {
			t.Fatal("error creating request body")
		}

		req, err := http.NewRequest(http.MethodPost, fullHost+"/login", bytes.NewBuffer(body))
		if err != nil {
			t.Fatalf("error creating request: %s", err.Error())
		}
		req.Header.Add("Content-Type", "application/json")

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("error in request")
		}

		responseBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal("error reading response body")
		}

		var serverResponse handler.AccessTokenServerResponse
		err = json.Unmarshal(responseBody, &serverResponse)
		if err != nil {
			t.Fatal("error unmarshalling response")
		}

		if serverResponse.Status != "ERROR" {
			t.Fatal("expected ERROR")
		}
	})

	var refreshTokenCookie string
	var accessToken string

	t.Run("correct password user login", func(t *testing.T) {
		form := handler.LoginForm{
			Username: "user@domain.com",
			Password: "asdfasdf",
		}
		body, err := json.Marshal(form)
		if err != nil {
			t.Fatal("error creating request body")
		}

		req, err := http.NewRequest(http.MethodPost, fullHost+"/login", bytes.NewBuffer(body))
		if err != nil {
			t.Fatalf("error creating request: %s", err.Error())
		}
		req.Header.Add("Content-Type", "application/json")

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("error in request")
		}

		responseBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal("error reading response body")
		}

		var serverResponse handler.AccessTokenServerResponse
		err = json.Unmarshal(responseBody, &serverResponse)
		if err != nil {
			t.Fatal("error unmarshalling response")
		}

		if serverResponse.Status != "SUCCESS" {
			t.Fatal("expected SUCCESS")
		}

		// grab the access JWT and cookie for later test cases
		// looks like: refresh-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJAZG9tYWluLmNvbSIsImV4cCI6MTYzOTcyNDc2Mn0.RrmQZSv_69nXGkGXPAGtz9P1j3mRzsGBZNa1Ibz6ZwE; Expires=Fri, 17 Dec 2021 07:06:02 GMT; HttpOnly
		refreshTokenCookie = res.Header.Get("Set-Cookie")
		i := strings.Index(refreshTokenCookie, ";")
		if i == -1 {
			t.Fatal("wrong format for refresh token cookie")
		}
		refreshTokenCookie = refreshTokenCookie[:i]
		accessToken = serverResponse.Data.AccessToken
	})

	t.Run("no refresh token cookie refresh", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, fullHost+"/refresh", nil)
		if err != nil {
			t.Fatalf("error creating request: %s", err.Error())
		}

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("error in request")
		}

		responseBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal("error reading response body")
		}

		var serverResponse handler.AccessTokenServerResponse
		err = json.Unmarshal(responseBody, &serverResponse)
		if err != nil {
			t.Fatal("error unmarshalling response")
		}

		if serverResponse.Status != "ERROR" {
			t.Fatal("expected ERROR")
		}
	})

	t.Run("invalid refresh token cookie refresh", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, fullHost+"/refresh", nil)
		if err != nil {
			t.Fatalf("error creating request: %s", err.Error())
		}
		req.Header.Add("Cookie", refreshTokenCookie+"asdf")

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("error in request")
		}

		responseBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal("error reading response body")
		}

		var serverResponse handler.AccessTokenServerResponse
		err = json.Unmarshal(responseBody, &serverResponse)
		if err != nil {
			t.Fatal("error unmarshalling response")
		}

		if serverResponse.Status != "ERROR" {
			t.Fatal("expected ERROR")
		}
	})

	t.Run("valid refresh token cookie refresh", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, fullHost+"/refresh", nil)
		if err != nil {
			t.Fatalf("error creating request: %s", err.Error())
		}
		req.Header.Add("Cookie", refreshTokenCookie)

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("error in request")
		}

		responseBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal("error reading response body")
		}

		var serverResponse handler.AccessTokenServerResponse
		err = json.Unmarshal(responseBody, &serverResponse)
		if err != nil {
			t.Fatal("error unmarshalling response")
		}

		if serverResponse.Status != "SUCCESS" {
			t.Fatal("expected SUCCESS")
		}
	})

	t.Run("no access token isLoggedIn", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, fullHost+"/isLoggedIn", nil)
		if err != nil {
			t.Fatalf("error creating request: %s", err.Error())
		}

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("error in request")
		}

		responseBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal("error reading response body")
		}

		var serverResponse handler.IsLoggedInServerResponse
		err = json.Unmarshal(responseBody, &serverResponse)
		if err != nil {
			t.Fatal("error unmarshalling response")
		}

		if serverResponse.Status != "SUCCESS" {
			t.Fatal("expected SUCCESS")
		}
		if serverResponse.Data.IsLoggedIn != false {
			t.Fatal("expected isLoggedIn false")
		}
	})

	t.Run("invalid access token isLoggedIn", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, fullHost+"/isLoggedIn", nil)
		if err != nil {
			t.Fatalf("error creating request: %s", err.Error())
		}

		req.Header.Add("Authorization", "Bearer "+accessToken+"asdf")

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("error in request")
		}

		responseBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal("error reading response body")
		}

		var serverResponse handler.IsLoggedInServerResponse
		err = json.Unmarshal(responseBody, &serverResponse)
		if err != nil {
			t.Fatal("error unmarshalling response")
		}

		if serverResponse.Status != "SUCCESS" {
			t.Fatal("expected SUCCESS")
		}
		if serverResponse.Data.IsLoggedIn != false {
			t.Fatal("expected isLoggedIn false")
		}
	})

	t.Run("valid access token isLoggedIn", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, fullHost+"/isLoggedIn", nil)
		if err != nil {
			t.Fatalf("error creating request: %s", err.Error())
		}

		req.Header.Add("Authorization", "Bearer "+accessToken)

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("error in request")
		}

		responseBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal("error reading response body")
		}

		var serverResponse handler.IsLoggedInServerResponse
		err = json.Unmarshal(responseBody, &serverResponse)
		if err != nil {
			t.Fatal("error unmarshalling response")
		}

		if serverResponse.Status != "SUCCESS" {
			t.Fatal("expected SUCCESS")
		}
		if serverResponse.Data.IsLoggedIn != true {
			t.Fatal("expected isLoggedIn true")
		}
	})

	t.Run("no access token api", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, fullHost+"/api/data", nil)
		if err != nil {
			t.Fatalf("error creating request: %s", err.Error())
		}

		req.Header.Add("Content-Type", "application/json")

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("error in request")
		}

		responseBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal("error reading response body")
		}

		var serverResponse handler.ServerResponse
		err = json.Unmarshal(responseBody, &serverResponse)
		if err != nil {
			t.Fatal("error unmarshalling response")
		}

		if serverResponse.Status != "ERROR" {
			t.Fatal("expected ERROR")
		}
	})

	t.Run("invalid access token api", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, fullHost+"/api/data", nil)
		if err != nil {
			t.Fatalf("error creating request: %s", err.Error())
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", "Bearer "+accessToken+"asdf")

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("error in request")
		}

		responseBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal("error reading response body")
		}

		var serverResponse handler.ServerResponse
		err = json.Unmarshal(responseBody, &serverResponse)
		if err != nil {
			t.Fatal("error unmarshalling response")
		}

		if serverResponse.Status != "ERROR" {
			t.Fatal("expected ERROR")
		}
	})

	t.Run("valid access token api", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, fullHost+"/api/data", nil)
		if err != nil {
			t.Fatalf("error creating request: %s", err.Error())
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", "Bearer "+accessToken)

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("error in request")
		}

		responseBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal("error reading response body")
		}

		var serverResponse handler.ServerResponse
		err = json.Unmarshal(responseBody, &serverResponse)
		if err != nil {
			t.Fatal("error unmarshalling response")
		}

		if serverResponse.Status != "SUCCESS" {
			t.Fatal("expected SUCCESS")
		}
	})
}
