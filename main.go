package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

type ssEventData struct {
	Name    string
	Message string
}

func main() {
	// 解析命令行参数
	target := flag.String("target", "", "proxy target URL")
	port := flag.String("port", "", "listen port")
	debug := flag.Bool("debug", false, "debug mode")
	flag.Parse()

	if *target == "" {
		panic("target URL is required")
	}

	if *port == "" {
		*port = "8080"
	}

	if !*debug {
		gin.SetMode(gin.ReleaseMode)
	}

	// 创建 Gin 实例
	r := gin.Default()

	// 设置代理路由
	r.Any("/*path", func(c *gin.Context) {

		path := fmt.Sprintf("%s%s", *target, c.Request.URL.Path)

		// 创建请求
		req, err := http.NewRequest(c.Request.Method, path, c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}

		// 设置请求头
		req.Header = c.Request.Header
		if c.Request.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}

		var dialer = &net.Dialer{Resolver: &net.Resolver{PreferGo: false}}
		var tr = &http.Transport{DialContext: dialer.DialContext}
		var client *http.Client = &http.Client{Transport: tr}

		// check if the proxy is set
		proxy := getProxy(false)
		if proxy != "" {
			proxyURL, err := url.Parse(proxy)
			if err != nil {
				c.JSON(http.StatusInternalServerError, err.Error())
				return
			}
			tr := &http.Transport{
				Proxy:       http.ProxyURL(proxyURL),
				DialContext: dialer.DialContext,
			}

			client = &http.Client{Transport: tr}
		}

		// Https SkipVerify false
		if strings.HasPrefix(*target, "https://") {

			tr = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext:     dialer.DialContext,
			}

			// check if the proxy is set
			proxy := getProxy(true)
			if proxy != "" {
				proxyURL, err := url.Parse(proxy)
				if err != nil {
					c.JSON(http.StatusInternalServerError, err.Error())
					return
				}

				tr.Proxy = http.ProxyURL(proxyURL)
			}

			client = &http.Client{Transport: tr}
		}
		defer tr.CloseIdleConnections()

		// 发送请求
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		resp, err := client.Do(req.WithContext(ctx))
		if err != nil {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			c.JSON(http.StatusInternalServerError, resp.Status)
			return
		}

		// copy Response header
		for key, values := range resp.Header {
			for _, value := range values {
				c.Writer.Header().Add(key, value)
			}
		}

		// SSE
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {

			chanStream := make(chan []byte, 1)
			chanError := make(chan error, 1)
			go func() {
				defer func() {
					close(chanError)
					close(chanStream)
				}()

				scanner := bufio.NewScanner(resp.Body)
				for scanner.Scan() {
					chanStream <- scanner.Bytes()
				}

				if err := scanner.Err(); err != nil {
					chanError <- err
				}
			}()

			c.Stream(func(w io.Writer) bool {
				select {
				case err := <-chanError:
					if err != nil {
						c.JSON(http.StatusInternalServerError, err.Error())
					}
					return false

				case msg := <-chanStream:
					msg = append(msg, []byte("\n")...)
					w.Write(msg)
					return true

				case <-ctx.Done():
					return false
				}
			})

			c.Status(200)
			return
		}

		// normal response
		rBody, err := ioutil.ReadAll(resp.Body) // response body is []byte
		if err != nil {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}

		if len(rBody) == 0 {
			c.Status(resp.StatusCode)
			return
		}

		c.Writer.Write(rBody)
		c.Status(resp.StatusCode)
	})

	fmt.Println("Server is running on port: ", *port)
	r.Run(fmt.Sprintf(":%s", *port))

}

func getProxy(https bool) string {
	if https {
		proxy := os.Getenv("HTTPS_PROXY")
		if proxy != "" {
			return proxy
		}
		return os.Getenv("https_proxy")
	}

	proxy := os.Getenv("HTTP_PROXY")
	if proxy != "" {
		return proxy
	}
	return os.Getenv("http_proxy")
}
