package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ArcadeAI/logical-extensions-examples/pkg/server"
)

//go:embed static
var staticFiles embed.FS

func main() {
	port := flag.Int("port", 8888, "Port to listen on")
	token := flag.String("token", "", "Bearer token for authentication (empty = no auth)")
	verbose := flag.Bool("verbose", true, "Log all requests to stdout")
	configFile := flag.String("config", "config.yaml", "Path to YAML configuration file")
	tlsEnabled := flag.Bool("tls", false, "Enable TLS/HTTPS")
	certFile := flag.String("cert", "", "Path to server certificate file (PEM)")
	keyFile := flag.String("key", "", "Path to server private key file (PEM)")
	caFile := flag.String("ca", "", "Path to CA certificate for client verification (enables mTLS)")
	flag.Parse()

	if *tlsEnabled {
		if *certFile == "" || *keyFile == "" {
			log.Fatal("TLS enabled but -cert and -key are required")
		}
	}

	// Initialize configuration manager
	cfgMgr := NewConfigManager(*configFile)

	// Try to load existing config file
	if _, err := os.Stat(*configFile); err == nil {
		if err := cfgMgr.LoadFromFile(); err != nil {
			log.Printf("Warning: Failed to load config from %s: %v", *configFile, err)
		} else {
			log.Printf("Loaded configuration from %s", *configFile)
		}
	} else {
		// Save default config
		if err := cfgMgr.SaveToFile(); err != nil {
			log.Printf("Warning: Failed to save default config to %s: %v", *configFile, err)
		} else {
			log.Printf("Created default configuration at %s", *configFile)
		}
	}

	// Watch config file for changes
	go cfgMgr.WatchFile()

	// Initialize hook server
	hookServer := NewHookServer(cfgMgr, *token, *verbose)

	// Start arcade client periodic fetch
	hookServer.arcadeClient.StartPeriodicFetch(cfgMgr)
	defer hookServer.arcadeClient.Stop()

	// Set up Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// Register CATE webhook handlers
	server.RegisterHandlers(router, hookServer)

	// API endpoints for the UI
	api := router.Group("/api")
	{
		// Configuration
		api.GET("/config", func(c *gin.Context) {
			c.JSON(http.StatusOK, cfgMgr.Get())
		})
		api.PUT("/config", func(c *gin.Context) {
			var cfg Config
			if err := c.ShouldBindJSON(&cfg); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			cfgMgr.Update(&cfg)
			if err := cfgMgr.SaveToFile(); err != nil {
				log.Printf("Warning: Failed to save config: %v", err)
			}
			c.JSON(http.StatusOK, gin.H{"message": "configuration updated"})
		})

		// Request logs
		api.GET("/logs", func(c *gin.Context) {
			logs := hookServer.GetLogs()
			c.JSON(http.StatusOK, gin.H{"count": len(logs), "logs": logs})
		})
		api.DELETE("/logs", func(c *gin.Context) {
			hookServer.ClearLogs()
			c.JSON(http.StatusOK, gin.H{"message": "logs cleared"})
		})

		// Server status
		api.GET("/status", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"status":        "running",
				"port":          *port,
				"auth_enabled":  *token != "",
				"tls_enabled":   *tlsEnabled,
				"config_file":   *configFile,
				"request_count": len(hookServer.GetLogs()),
			})
		})

		// PII test endpoint
		api.POST("/pii/test", func(c *gin.Context) {
			var req struct {
				Text string `json:"text"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			cfg := cfgMgr.Get()
			piiCfg := cfg.PII
			if piiCfg == nil {
				piiCfg = &PIIConfig{
					Enabled: true,
					Mode:    "redact",
					Types:   PIITypes{Email: true, IPAddress: true, SSN: true, PhoneNumber: true, CreditCard: true, DateOfBirth: true},
				}
			}
			detector := NewPIIDetector()
			redacted, matches := detector.RedactText(req.Text, piiCfg)
			c.JSON(http.StatusOK, gin.H{
				"original": req.Text,
				"redacted": redacted,
				"matches":  matches,
			})
		})

		// Arcade tool catalog
		api.POST("/arcade/fetch", func(c *gin.Context) {
			cfg := cfgMgr.Get()
			ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
			defer cancel()
			if err := hookServer.arcadeClient.FetchTools(ctx, cfg.Arcade); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "tools fetched", "count": len(hookServer.arcadeClient.GetTools())})
		})
		api.GET("/arcade/tools", func(c *gin.Context) {
			tools := hookServer.arcadeClient.GetTools()
			lastFetch := hookServer.arcadeClient.GetLastFetch()
			c.JSON(http.StatusOK, gin.H{
				"tools":      tools,
				"count":      len(tools),
				"last_fetch": lastFetch,
			})
		})

		// A/B testing info
		api.GET("/ab/assignments", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"assignments": hookServer.abEngine.GetAssignments(),
			})
		})
		api.DELETE("/ab/assignments", func(c *gin.Context) {
			hookServer.abEngine.ClearAssignments()
			c.JSON(http.StatusOK, gin.H{"message": "assignments cleared"})
		})
	}

	// Serve the web UI
	staticSub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal("Failed to create sub filesystem:", err)
	}
	router.GET("/", func(c *gin.Context) {
		data, err := fs.ReadFile(staticSub, "index.html")
		if err != nil {
			c.String(http.StatusInternalServerError, "Failed to load UI: %v", err)
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	})

	printBanner(*port, *token, *tlsEnabled, *caFile, *configFile)

	addr := fmt.Sprintf(":%d", *port)

	if *tlsEnabled {
		tlsConfig, err := buildTLSConfig(*caFile)
		if err != nil {
			log.Fatal("Failed to configure TLS:", err)
		}

		srv := &http.Server{
			Addr:      addr,
			Handler:   router,
			TLSConfig: tlsConfig,
		}

		if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil {
			log.Fatal("Failed to start TLS server:", err)
		}
	} else {
		if err := router.Run(addr); err != nil {
			log.Fatal("Failed to start server:", err)
		}
	}
}

func buildTLSConfig(caFile string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

func printBanner(port int, token string, tlsEnabled bool, caFile, configFile string) {
	protocol := "http"
	if tlsEnabled {
		protocol = "https"
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  CATE Hook Server (Full)")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Port:        %d\n", port)
	fmt.Printf("  Auth:        %s\n", authStatus(token))
	fmt.Printf("  TLS:         %s\n", tlsStatus(tlsEnabled, caFile))
	fmt.Printf("  Config:      %s\n", configFile)
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println("  Web UI:")
	fmt.Printf("    %s://localhost:%d/\n", protocol, port)
	fmt.Println()
	fmt.Println("  Webhook Endpoints:")
	fmt.Printf("    GET  %s://localhost:%d/health\n", protocol, port)
	fmt.Printf("    POST %s://localhost:%d/access\n", protocol, port)
	fmt.Printf("    POST %s://localhost:%d/pre\n", protocol, port)
	fmt.Printf("    POST %s://localhost:%d/post\n", protocol, port)
	fmt.Println()
	fmt.Println("  API Endpoints:")
	fmt.Printf("    GET/PUT %s://localhost:%d/api/config\n", protocol, port)
	fmt.Printf("    GET/DEL %s://localhost:%d/api/logs\n", protocol, port)
	fmt.Printf("    GET     %s://localhost:%d/api/status\n", protocol, port)
	fmt.Printf("    POST    %s://localhost:%d/api/pii/test\n", protocol, port)
	fmt.Printf("    POST    %s://localhost:%d/api/arcade/fetch\n", protocol, port)
	fmt.Printf("    GET     %s://localhost:%d/api/arcade/tools\n", protocol, port)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  Ready to receive webhook requests...")
	fmt.Println()
}

func authStatus(token string) string {
	if token == "" {
		return "disabled"
	}
	return fmt.Sprintf("enabled (token: %s...)", token[:min(8, len(token))])
}

func tlsStatus(enabled bool, caFile string) string {
	if !enabled {
		return "disabled (HTTP)"
	}
	if caFile != "" {
		return "mTLS enabled (client cert required)"
	}
	return "TLS enabled (HTTPS)"
}
