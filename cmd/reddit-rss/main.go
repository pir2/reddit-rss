package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
	"sync"

	"github.com/getsentry/sentry-go"
	sentryhttp "github.com/getsentry/sentry-go/http"
	"github.com/trashhalo/reddit-rss/pkg/client"
	cache "github.com/victorspringer/http-cache"
	"github.com/victorspringer/http-cache/adapter/redis"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

var mu sync.Mutex

func main() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	err := sentry.Init(sentry.ClientOptions{
		Dsn: os.Getenv("SENTRY_DSN"),
	})

	if err != nil {
		panic(err)
	}

	log.Println("starting reddit-rss")

	sentryHandler := sentryhttp.New(sentryhttp.Options{})

	http.HandleFunc("/info/ping", sentryHandler.HandleFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))

	limiter := rate.NewLimiter(rate.Limit(100.0/60.0), 1) // 1 burst size
	
	var rssHandler http.Handler
	rssHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var limit_counter int = 0
		for !limiter.Allow() && limit_counter <= 30 {
			log.Printf("Sleeping for 5s")
			time.Sleep(1 * time.Second)
			limit_counter++
			// If the rate limit is exceeded, return HTTP 429 (Too Many Requests)
			//http.Error(w, "Too many requests, please try again later", http.StatusTooManyRequests)
			//return
		}
		httpClient := http.DefaultClient
		var token *oauth2.Token
		baseApiUrl := "https://www.reddit.com"
		oauthClientID := os.Getenv("OAUTH_CLIENT_ID")
		if oauthClientID != "" {
			oauthClientSecret := os.Getenv("OAUTH_CLIENT_SECRET")
			oauthCfg := &oauth2.Config{
				ClientID:     oauthClientID,
				ClientSecret: oauthClientSecret,
				Endpoint: oauth2.Endpoint{
					TokenURL:  "https://www.reddit.com/api/v1/access_token",
					AuthStyle: oauth2.AuthStyleInHeader,
				},
			}
			// login with reddit user password
			username := os.Getenv("REDDIT_USERNAME")
			password := os.Getenv("REDDIT_PASSWORD")
			token, err = oauthCfg.PasswordCredentialsToken(r.Context(), username, password)
			var token_counter int = 0
			for err != nil && token_counter <=30 {
				time.Sleep(1 * time.Second)
				token, err = oauthCfg.PasswordCredentialsToken(r.Context(), username, password)
				token_counter++
				//http.Error(w, err.Error(), 500)
				//return
			}
			baseApiUrl = "https://oauth.reddit.com"
		}
		userAgent := os.Getenv("USER_AGENT")
		if userAgent == "" {
			userAgent = "reddit-rss 1.0"
		}
		redditClient := &client.RedditClient{
			HttpClient: httpClient,
			Token:      token,
			UserAgent:  userAgent,
		}
		client.RssHandler(baseApiUrl, time.Now, redditClient, client.GetArticle, w, r)
	})

	redisCacheUrl := os.Getenv("FLY_REDIS_CACHE_URL")
	if redisCacheUrl != "" {
		u, err := url.Parse(redisCacheUrl)
		if err != nil {
			log.Fatal(err)
		}
		pass, _ := u.User.Password()
		ringOpt := &redis.RingOptions{
			Addrs: map[string]string{
				"server": u.Host,
			},
			Password: pass,
		}
		cacheClient, err := cache.NewClient(
			cache.ClientWithAdapter(redis.NewAdapter(ringOpt)),
			cache.ClientWithTTL(60*time.Minute),
			cache.ClientWithRefreshKey("opn"),
		)
		if err != nil {
			log.Fatal(err)
		}
		rssHandler = cacheClient.Middleware(rssHandler)
	}

	http.Handle("/", rssHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
