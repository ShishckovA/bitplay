package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"net/url"
	"path/filepath"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/storage"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/net/proxy"
)

var (
	currentSettings Settings
	settingsMutex   sync.RWMutex
)

type TorrentSession struct {
	Client   *torrent.Client
	Torrent  *torrent.Torrent
	Port     int
	LastUsed time.Time

	statsMu              sync.Mutex
	lastStatsAt          time.Time
	lastBytesReadData    int64
	lastBytesReadUseful  int64
	lastBytesWrittenData int64
}

type Settings struct {
	EnableProxy    bool   `json:"enableProxy"`
	ProxyURL       string `json:"proxyUrl"`
	EnableProwlarr bool   `json:"enableProwlarr"`
	ProwlarrHost   string `json:"prowlarrHost"`
	ProwlarrApiKey string `json:"prowlarrApiKey"`
	EnableJackett  bool   `json:"enableJackett"`
	JackettHost    string `json:"jackettHost"`
	JackettApiKey  string `json:"jackettApiKey"`
}

type ProxySettings struct {
	EnableProxy bool   `json:"enableProxy"`
	ProxyURL    string `json:"proxyUrl"`
}

type ProwlarrSettings struct {
	EnableProwlarr bool   `json:"enableProwlarr"`
	ProwlarrHost   string `json:"prowlarrHost"`
	ProwlarrApiKey string `json:"prowlarrApiKey"`
}

type JackettSettings struct {
	EnableJackett bool   `json:"enableJackett"`
	JackettHost   string `json:"jackettHost"`
	JackettApiKey string `json:"jackettApiKey"`
}

type StoredTorrentFile struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
	Size  int64  `json:"size"`
}

type StoredTorrent struct {
	ID         string              `json:"id"`
	Magnet     string              `json:"magnet"`
	Name       string              `json:"name"`
	Files      []StoredTorrentFile `json:"files"`
	MetaInfo   []byte              `json:"metaInfo,omitempty"`
	AddedAt    time.Time           `json:"addedAt"`
	LastUsedAt time.Time           `json:"lastUsedAt"`
}

type StoredTorrentView struct {
	ID         string              `json:"id"`
	Magnet     string              `json:"magnet"`
	Name       string              `json:"name"`
	Files      []StoredTorrentFile `json:"files"`
	AddedAt    time.Time           `json:"addedAt"`
	LastUsedAt time.Time           `json:"lastUsedAt"`
}

type TorrentDiagnosticsResponse struct {
	SessionID             string    `json:"sessionId"`
	TorrentName           string    `json:"torrentName"`
	TorrentLengthBytes    int64     `json:"torrentLengthBytes"`
	BytesCompleted        int64     `json:"bytesCompleted"`
	BytesMissing          int64     `json:"bytesMissing"`
	Progress              float64   `json:"progress"`
	TotalPeers            int       `json:"totalPeers"`
	PendingPeers          int       `json:"pendingPeers"`
	ActivePeers           int       `json:"activePeers"`
	ConnectedSeeders      int       `json:"connectedSeeders"`
	HalfOpenPeers         int       `json:"halfOpenPeers"`
	PiecesComplete        int       `json:"piecesComplete"`
	DownloadedDataBytes   int64     `json:"downloadedDataBytes"`
	DownloadedUsefulBytes int64     `json:"downloadedUsefulBytes"`
	UploadedDataBytes     int64     `json:"uploadedDataBytes"`
	DownloadRateBps       float64   `json:"downloadRateBps"`
	UsefulDownloadRateBps float64   `json:"usefulDownloadRateBps"`
	UploadRateBps         float64   `json:"uploadRateBps"`
	StoragePath           string    `json:"storagePath,omitempty"`
	StorageTotalBytes     uint64    `json:"storageTotalBytes,omitempty"`
	StorageFreeBytes      uint64    `json:"storageFreeBytes,omitempty"`
	StorageDiagnosticsErr string    `json:"storageDiagnosticsErr,omitempty"`
	Timestamp             time.Time `json:"timestamp"`
}

type BasicAuthConfig struct {
	Enabled  bool
	Username string
	Password string
	Realm    string
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	bytes      int
}

type contextKey string

const requestIDContextKey contextKey = "request_id"

const (
	defaultPlayerDiagnosticsLogPath    = "/tmp/bitplay-player-diagnostics.ndjson"
	defaultTorrentStoragePath          = "./torrent-data"
	maxPlayerDiagnosticsPayloadBytes   = 512 * 1024
	defaultPlayerDiagnosticsReadLimit  = 200
	maxPlayerDiagnosticsReadLimit      = 2000
	videoStreamReadaheadBytes          = 64 * 1024 * 1024
	defaultFFmpegBinary                = "ffmpeg"
	defaultFFprobeBinary               = "ffprobe"
	transcodeStartupMinContiguousBytes = 2 * 1024 * 1024
	transcodeStartupWaitTimeout        = 20 * time.Second
	transcodeStartupPollInterval       = 250 * time.Millisecond
	transcodeDurationProbeTimeout      = 6 * time.Second
	transcodeDurationProbeMaxBytes     = 32 * 1024 * 1024
	transcodeDurationProbeRetryDelay   = 20 * time.Second
)

func (w *loggingResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *loggingResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	requestID, _ := ctx.Value(requestIDContextKey).(string)
	return requestID
}

func newRequestID() string {
	return fmt.Sprintf("req-%08x", requestSeq.Add(1))
}

func summarizeIDs(ids []string, limit int) string {
	if len(ids) == 0 {
		return "[]"
	}

	sort.Strings(ids)
	if limit <= 0 || len(ids) <= limit {
		return "[" + strings.Join(ids, ", ") + "]"
	}

	return fmt.Sprintf("[%s, ... (+%d more)]", strings.Join(ids[:limit], ", "), len(ids)-limit)
}

func inMemorySessionIDs() []string {
	ids := make([]string, 0)
	sessions.Range(func(key, _ interface{}) bool {
		id := normalizeTorrentID(fmt.Sprintf("%v", key))
		if id != "" {
			ids = append(ids, id)
		}
		return true
	})
	return ids
}

func storedTorrentIDs() ([]string, error) {
	records, err := listStoredTorrents()
	if err != nil {
		return nil, err
	}

	return extractStoredTorrentIDs(records), nil
}

func extractStoredTorrentIDs(records []StoredTorrent) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		id := normalizeTorrentID(record.ID)
		if id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

var (
	sessions                sync.Map
	usedPorts               sync.Map
	portMutex               sync.Mutex
	requestSeq              atomic.Uint64
	playerDiagnosticsFileMu sync.Mutex
	transcodeDurationHints  sync.Map
	transcodeDurationProbes sync.Map

	torrentDB *bolt.DB
)

const torrentBucketName = "torrents"

// Helper function to format file sizes
func formatSize(sizeInBytes float64) string {
	if sizeInBytes < 1024 {
		return fmt.Sprintf("%.0f B", sizeInBytes)
	}

	sizeInKB := sizeInBytes / 1024
	if sizeInKB < 1024 {
		return fmt.Sprintf("%.2f KB", sizeInKB)
	}

	sizeInMB := sizeInKB / 1024
	if sizeInMB < 1024 {
		return fmt.Sprintf("%.2f MB", sizeInMB)
	}

	sizeInGB := sizeInMB / 1024
	return fmt.Sprintf("%.2f GB", sizeInGB)
}

func nonNegativeDelta(current, previous int64) int64 {
	if current <= previous {
		return 0
	}
	return current - previous
}

func readStorageDiagnostics(path string) (totalBytes uint64, freeBytes uint64, err error) {
	var stats syscall.Statfs_t
	if err := syscall.Statfs(path, &stats); err != nil {
		return 0, 0, err
	}
	blockSize := uint64(stats.Bsize)
	totalBytes = stats.Blocks * blockSize
	freeBytes = stats.Bavail * blockSize
	return totalBytes, freeBytes, nil
}

func buildTorrentDiagnostics(sessionID string, session *TorrentSession) TorrentDiagnosticsResponse {
	stats := session.Torrent.Stats()
	now := time.Now()

	bytesReadData := stats.BytesReadData.Int64()
	bytesReadUseful := stats.BytesReadUsefulData.Int64()
	bytesWrittenData := stats.BytesWrittenData.Int64()

	var downloadRateBps float64
	var usefulDownloadRateBps float64
	var uploadRateBps float64

	session.statsMu.Lock()
	if !session.lastStatsAt.IsZero() {
		elapsed := now.Sub(session.lastStatsAt).Seconds()
		if elapsed > 0 {
			downloadRateBps = float64(nonNegativeDelta(bytesReadData, session.lastBytesReadData)) / elapsed
			usefulDownloadRateBps = float64(nonNegativeDelta(bytesReadUseful, session.lastBytesReadUseful)) / elapsed
			uploadRateBps = float64(nonNegativeDelta(bytesWrittenData, session.lastBytesWrittenData)) / elapsed
		}
	}
	session.lastStatsAt = now
	session.lastBytesReadData = bytesReadData
	session.lastBytesReadUseful = bytesReadUseful
	session.lastBytesWrittenData = bytesWrittenData
	session.statsMu.Unlock()

	length := session.Torrent.Length()
	completed := session.Torrent.BytesCompleted()
	missing := session.Torrent.BytesMissing()
	progress := 0.0
	if length > 0 {
		progress = (float64(completed) / float64(length)) * 100
	}

	storagePath := defaultTorrentStoragePath
	storageTotal, storageFree, storageErr := readStorageDiagnostics(storagePath)
	storageErrText := ""
	if storageErr != nil {
		storageErrText = storageErr.Error()
	}

	return TorrentDiagnosticsResponse{
		SessionID:             sessionID,
		TorrentName:           session.Torrent.Name(),
		TorrentLengthBytes:    length,
		BytesCompleted:        completed,
		BytesMissing:          missing,
		Progress:              progress,
		TotalPeers:            stats.TotalPeers,
		PendingPeers:          stats.PendingPeers,
		ActivePeers:           stats.ActivePeers,
		ConnectedSeeders:      stats.ConnectedSeeders,
		HalfOpenPeers:         stats.HalfOpenPeers,
		PiecesComplete:        stats.PiecesComplete,
		DownloadedDataBytes:   bytesReadData,
		DownloadedUsefulBytes: bytesReadUseful,
		UploadedDataBytes:     bytesWrittenData,
		DownloadRateBps:       downloadRateBps,
		UsefulDownloadRateBps: usefulDownloadRateBps,
		UploadRateBps:         uploadRateBps,
		StoragePath:           storagePath,
		StorageTotalBytes:     storageTotal,
		StorageFreeBytes:      storageFree,
		StorageDiagnosticsErr: storageErrText,
		Timestamp:             now,
	}
}

func resolvePlayerDiagnosticsLogPath() string {
	if configuredPath := strings.TrimSpace(os.Getenv("BITPLAY_PLAYER_DIAGNOSTICS_LOG")); configuredPath != "" {
		return configuredPath
	}
	return defaultPlayerDiagnosticsLogPath
}

func appendPlayerDiagnosticsLine(logPath string, line []byte) error {
	playerDiagnosticsFileMu.Lock()
	defer playerDiagnosticsFileMu.Unlock()

	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return err
	}

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(line); err != nil {
		return err
	}
	_, err = file.Write([]byte("\n"))
	return err
}

func readRecentPlayerDiagnosticsLines(logPath string, limit int, sessionID string) ([]string, error) {
	playerDiagnosticsFileMu.Lock()
	defer playerDiagnosticsFileMu.Unlock()

	file, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer file.Close()

	filterToken := ""
	if sessionID != "" {
		filterToken = `"sessionId":"` + sessionID + `"`
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	lines := make([]string, 0, limit)
	for scanner.Scan() {
		line := scanner.Text()
		if filterToken != "" && !strings.Contains(line, filterToken) {
			continue
		}

		if len(lines) == limit {
			copy(lines, lines[1:])
			lines[len(lines)-1] = line
			continue
		}
		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func isVideoExtension(ext string) bool {
	switch strings.ToLower(strings.TrimSpace(ext)) {
	case ".mp4", ".m4v", ".mkv", ".webm", ".avi":
		return true
	default:
		return false
	}
}

type fileProgressSnapshot struct {
	TotalBytes      int64
	CompletedBytes  int64
	ContiguousBytes int64
	PiecesTotal     int
	PiecesComplete  int
}

func buildFileProgressSnapshot(file *torrent.File) fileProgressSnapshot {
	snapshot := fileProgressSnapshot{
		TotalBytes: file.Length(),
	}

	states := file.State()
	contiguous := true
	for _, piece := range states {
		snapshot.PiecesTotal++
		if piece.Complete {
			snapshot.PiecesComplete++
			snapshot.CompletedBytes += piece.Bytes
			if contiguous {
				snapshot.ContiguousBytes += piece.Bytes
			}
			continue
		}
		contiguous = false
	}

	return snapshot
}

var (
	proxyTransport = &http.Transport{
		// copy your existing timeouts & DialContext logic here...
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConnsPerHost:   10,
	}
	proxyClient = &http.Client{
		Transport: proxyTransport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			for k, vv := range via[0].Header {
				if _, ok := req.Header[k]; !ok {
					req.Header[k] = vv
				}
			}
			return nil
		},
	}
)

func createSelectiveProxyClient() *http.Client {
	settingsMutex.RLock()
	defer settingsMutex.RUnlock()

	if !currentSettings.EnableProxy {
		return &http.Client{Timeout: 30 * time.Second}
	}
	// Reconfigure proxyTransport’s DialContext if URL changed:
	dialer, _ := createProxyDialer(currentSettings.ProxyURL)
	proxyTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.Dial(network, addr)
	}
	// Drop any old idle conns after reconfiguration:
	proxyTransport.CloseIdleConnections()

	return proxyClient
}

// Create a proxy dialer for SOCKS5
func createProxyDialer(proxyURL string) (proxy.Dialer, error) {
	proxyURLParsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy URL: %v", err)
	}

	// Extract auth information
	auth := &proxy.Auth{}
	if proxyURLParsed.User != nil {
		auth.User = proxyURLParsed.User.Username()
		if password, ok := proxyURLParsed.User.Password(); ok {
			auth.Password = password
		}
	}

	// Create a SOCKS5 dialer
	return proxy.SOCKS5("tcp", proxyURLParsed.Host, auth, proxy.Direct)
}

// Implement a port allocation function to prevent conflicts
func getAvailablePort() int {
	portMutex.Lock()
	defer portMutex.Unlock()

	// Try up to 50 times to find an unused port
	for i := 0; i < 50; i++ {
		// Generate a random port in the high range
		port := 10000 + rand.Intn(50000)

		// Check if this port is already in use by our app
		if _, exists := usedPorts.Load(port); !exists {
			// Mark this port as used
			usedPorts.Store(port, true)
			return port
		}
	}

	// If we can't find an available port, return a very high random port
	// as a last resort
	return 60000 + rand.Intn(5000)
}

// Release a port when we're done with it
func releasePort(port int) {
	portMutex.Lock()
	defer portMutex.Unlock()
	usedPorts.Delete(port)
}

// Initialize the torrent client with proxy settings
func initTorrentWithProxy() (*torrent.Client, int, error) {
	settingsMutex.RLock()
	enableProxy := currentSettings.EnableProxy
	proxyURL := currentSettings.ProxyURL
	settingsMutex.RUnlock()

	config := torrent.NewDefaultClientConfig()
	config.DefaultStorage = storage.NewFile("./torrent-data")
	port := getAvailablePort()
	config.ListenPort = port

	if enableProxy {
		log.Println("Creating torrent client with proxy...")
		os.Setenv("ALL_PROXY", proxyURL)
		os.Setenv("SOCKS_PROXY", proxyURL)
		os.Setenv("HTTP_PROXY", proxyURL)
		os.Setenv("HTTPS_PROXY", proxyURL)

		proxyDialer, err := createProxyDialer(proxyURL)
		if err != nil {
			releasePort(port)
			return nil, port, fmt.Errorf("could not create proxy dialer: %v", err)
		}

		config.HTTPProxy = func(*http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		}

		client, err := torrent.NewClient(config)
		if err != nil {
			releasePort(port)
			return nil, port, err
		}

		setValue(client, "dialerNetwork", func(ctx context.Context, network, addr string) (net.Conn, error) {
			return proxyDialer.Dial(network, addr)
		})

		return client, port, nil
	}

	log.Println("Creating torrent client without proxy...")
	os.Unsetenv("ALL_PROXY")
	os.Unsetenv("SOCKS_PROXY")
	os.Unsetenv("HTTP_PROXY")
	os.Unsetenv("HTTPS_PROXY")

	client, err := torrent.NewClient(config)
	if err != nil {
		releasePort(port)
		return nil, port, err
	}
	return client, port, nil
}

// Helper function to try to set a field value using reflection
// This is a bit hacky but might help override the client's dialer
func setValue(obj interface{}, fieldName string, value interface{}) {
	// This is a best-effort approach that may not work with all library versions
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Warning: Could not set %s field: %v", fieldName, r)
		}
	}()

	reflectValue := reflect.ValueOf(obj).Elem()
	field := reflectValue.FieldByName(fieldName)

	if field.IsValid() && field.CanSet() {
		field.Set(reflect.ValueOf(value))
		log.Printf("Successfully set %s to use proxy", fieldName)
	}
}

// Override system settings with our proxy
func init() {

	// check if settings.json exists
	if _, err := os.Stat("config/settings.json"); os.IsNotExist(err) {
		log.Println("settings.json not found, creating default settings")
		defaultSettings := Settings{
			EnableProxy:    false,
			ProxyURL:       "",
			EnableProwlarr: false,
			ProwlarrHost:   "",
			ProwlarrApiKey: "",
			EnableJackett:  false,
			JackettHost:    "",
			JackettApiKey:  "",
		}
		// Create the config directory if it doesn't exist
		if err := os.MkdirAll("config", 0755); err != nil {
			log.Fatalf("Failed to create config directory: %v", err)
		}
		settingsFile, err := os.Create("config/settings.json")
		if err != nil {
			log.Fatalf("Failed to create settings.json: %v", err)
		}
		defer settingsFile.Close()
		encoder := json.NewEncoder(settingsFile)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(defaultSettings); err != nil {
			log.Fatalf("Failed to encode default settings: %v", err)
		}
		log.Println("Default settings created in settings.json")
	}

	// Load settings from settings.json
	settingsFile, err := os.Open("config/settings.json")
	if err != nil {
		log.Fatalf("Failed to open settings.json: %v", err)
	}
	defer settingsFile.Close()

	var s Settings
	if err := json.NewDecoder(settingsFile).Decode(&s); err != nil {
		log.Fatalf("Failed to decode settings.json: %v", err)
	}

	settingsMutex.Lock()
	currentSettings = s
	settingsMutex.Unlock()
}

func initTorrentStore(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create torrent db directory: %w", err)
	}

	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return fmt.Errorf("failed to open torrent db: %w", err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(torrentBucketName))
		return err
	}); err != nil {
		db.Close()
		return fmt.Errorf("failed to initialize torrent db bucket: %w", err)
	}

	torrentDB = db
	return nil
}

func normalizeTorrentID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

func extractInfoHashFromMagnet(magnetURI string) string {
	parsed, err := url.Parse(strings.TrimSpace(magnetURI))
	if err != nil || !strings.EqualFold(parsed.Scheme, "magnet") {
		return ""
	}

	for _, xt := range parsed.Query()["xt"] {
		if !strings.HasPrefix(strings.ToLower(xt), "urn:btih:") {
			continue
		}

		hashPart := strings.TrimSpace(xt[len("urn:btih:"):])
		switch len(hashPart) {
		case 40:
			if _, err := hex.DecodeString(hashPart); err == nil {
				return strings.ToLower(hashPart)
			}
		case 32:
			decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(hashPart))
			if err == nil && len(decoded) == 20 {
				return hex.EncodeToString(decoded)
			}
		}
	}

	return ""
}

func storeTorrentRecord(record StoredTorrent) error {
	if torrentDB == nil {
		return errors.New("torrent db is not initialized")
	}

	record.ID = normalizeTorrentID(record.ID)
	if record.ID == "" {
		return errors.New("empty torrent id")
	}

	now := time.Now().UTC()
	if record.LastUsedAt.IsZero() {
		record.LastUsedAt = now
	}

	return torrentDB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(torrentBucketName))
		if bucket == nil {
			return errors.New("torrent bucket is missing")
		}

		key := []byte(record.ID)
		existingRaw := bucket.Get(key)
		if len(existingRaw) > 0 {
			var existing StoredTorrent
			if err := json.Unmarshal(existingRaw, &existing); err == nil {
				if record.Magnet == "" {
					record.Magnet = existing.Magnet
				}
				if record.Name == "" {
					record.Name = existing.Name
				}
				if len(record.Files) == 0 {
					record.Files = existing.Files
				}
				if len(record.MetaInfo) == 0 {
					record.MetaInfo = existing.MetaInfo
				}
				if record.AddedAt.IsZero() {
					record.AddedAt = existing.AddedAt
				}
			}
		}

		if record.AddedAt.IsZero() {
			record.AddedAt = now
		}

		payload, err := json.Marshal(record)
		if err != nil {
			return err
		}

		return bucket.Put(key, payload)
	})
}

func markStoredTorrentUsed(id string) {
	id = normalizeTorrentID(id)
	if id == "" || torrentDB == nil {
		return
	}

	_ = torrentDB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(torrentBucketName))
		if bucket == nil {
			return nil
		}

		raw := bucket.Get([]byte(id))
		if len(raw) == 0 {
			return nil
		}

		var existing StoredTorrent
		if err := json.Unmarshal(raw, &existing); err != nil {
			return nil
		}

		existing.LastUsedAt = time.Now().UTC()
		updated, err := json.Marshal(existing)
		if err != nil {
			return nil
		}

		return bucket.Put([]byte(id), updated)
	})
}

func getStoredTorrent(id string) (*StoredTorrent, error) {
	if torrentDB == nil {
		return nil, errors.New("torrent db is not initialized")
	}

	id = normalizeTorrentID(id)
	if id == "" {
		return nil, nil
	}

	var result *StoredTorrent
	err := torrentDB.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(torrentBucketName))
		if bucket == nil {
			return errors.New("torrent bucket is missing")
		}

		raw := bucket.Get([]byte(id))
		if len(raw) == 0 {
			return nil
		}

		var record StoredTorrent
		if err := json.Unmarshal(raw, &record); err != nil {
			return err
		}

		result = &record
		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

func listStoredTorrents() ([]StoredTorrent, error) {
	if torrentDB == nil {
		return nil, errors.New("torrent db is not initialized")
	}

	var results []StoredTorrent
	err := torrentDB.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(torrentBucketName))
		if bucket == nil {
			return errors.New("torrent bucket is missing")
		}

		return bucket.ForEach(func(_, value []byte) error {
			var record StoredTorrent
			if err := json.Unmarshal(value, &record); err != nil {
				return err
			}
			results = append(results, record)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(results, func(i, j int) bool {
		left := results[i].LastUsedAt
		if left.IsZero() {
			left = results[i].AddedAt
		}
		right := results[j].LastUsedAt
		if right.IsZero() {
			right = results[j].AddedAt
		}
		return left.After(right)
	})

	return results, nil
}

func buildStoredTorrentFromSession(sessionID, magnet string, t *torrent.Torrent) StoredTorrent {
	files := make([]StoredTorrentFile, 0, len(t.Files()))
	for i, file := range t.Files() {
		files = append(files, StoredTorrentFile{
			Index: i,
			Name:  file.DisplayPath(),
			Size:  file.Length(),
		})
	}

	var metaBytes []byte
	mi := t.Metainfo()
	var buf bytes.Buffer
	if err := mi.Write(&buf); err == nil && buf.Len() > 0 {
		metaBytes = buf.Bytes()
	}

	name := strings.TrimSpace(t.Name())
	if name == "" {
		name = sessionID
	}

	return StoredTorrent{
		ID:         normalizeTorrentID(sessionID),
		Magnet:     strings.TrimSpace(magnet),
		Name:       name,
		Files:      files,
		MetaInfo:   metaBytes,
		LastUsedAt: time.Now().UTC(),
	}
}

func toStoredTorrentView(record StoredTorrent) StoredTorrentView {
	return StoredTorrentView{
		ID:         record.ID,
		Magnet:     record.Magnet,
		Name:       record.Name,
		Files:      record.Files,
		AddedAt:    record.AddedAt,
		LastUsedAt: record.LastUsedAt,
	}
}

func parseFileIndex(fileIndexPathPart string, maxFiles int) (int, error) {
	fileIndexString := strings.TrimSuffix(fileIndexPathPart, ".vtt")
	fileIndex, err := strconv.Atoi(fileIndexString)
	if err != nil {
		return 0, errors.New("invalid file index")
	}

	if fileIndex < 0 || fileIndex >= maxFiles {
		return 0, errors.New("file index out of range")
	}

	return fileIndex, nil
}

func parseStartSeconds(raw string) (float64, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, nil
	}

	start, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, errors.New("invalid start parameter")
	}
	if start < 0 {
		return 0, errors.New("start must be greater than or equal to 0")
	}

	return start, nil
}

func resolveFFmpegBinary() string {
	if configured := strings.TrimSpace(os.Getenv("BITPLAY_FFMPEG_BIN")); configured != "" {
		return configured
	}
	return defaultFFmpegBinary
}

func resolveFFprobeBinary() string {
	if configured := strings.TrimSpace(os.Getenv("BITPLAY_FFPROBE_BIN")); configured != "" {
		return configured
	}
	return defaultFFprobeBinary
}

func resolveInternalBasicAuthHeader() string {
	username := os.Getenv("BITPLAY_AUTH_USERNAME")
	password := os.Getenv("BITPLAY_AUTH_PASSWORD")
	if username == "" || password == "" {
		return ""
	}

	token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return "Authorization: Basic " + token + "\r\n"
}

func sanitizeFFmpegArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}

	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		out = append(out, args[i])
		if args[i] == "-headers" && i+1 < len(args) {
			out = append(out, "<redacted>")
			i++
		}
	}
	return out
}

func parseDurationSeconds(raw string) float64 {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0
	}

	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	if seconds <= 0 {
		return 0
	}
	if seconds > 7*24*60*60 {
		return 0
	}
	return seconds
}

func extractDurationFromFFprobePayload(payload []byte) float64 {
	if len(bytes.TrimSpace(payload)) == 0 {
		return 0
	}

	type ffprobeStream struct {
		CodecType string `json:"codec_type"`
		Duration  string `json:"duration"`
	}
	type ffprobeFormat struct {
		Duration string `json:"duration"`
	}
	type ffprobeResult struct {
		Format  ffprobeFormat   `json:"format"`
		Streams []ffprobeStream `json:"streams"`
	}

	var result ffprobeResult
	if err := json.Unmarshal(payload, &result); err != nil {
		return 0
	}

	if formatDuration := parseDurationSeconds(result.Format.Duration); formatDuration > 0 {
		return formatDuration
	}

	videoDuration := 0.0
	maxDuration := 0.0
	for _, stream := range result.Streams {
		streamDuration := parseDurationSeconds(stream.Duration)
		if streamDuration <= 0 {
			continue
		}
		if streamDuration > maxDuration {
			maxDuration = streamDuration
		}
		if stream.CodecType == "video" && streamDuration > videoDuration {
			videoDuration = streamDuration
		}
	}
	if videoDuration > 0 {
		return videoDuration
	}
	return maxDuration
}

func probeVideoDurationSeconds(reqID string, sessionID string, fileIndex int, file *torrent.File, fileName string) (float64, error) {
	ffprobeBinary := resolveFFprobeBinary()
	if _, err := exec.LookPath(ffprobeBinary); err != nil {
		return 0, fmt.Errorf("ffprobe not available: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), transcodeDurationProbeTimeout)
	defer cancel()

	cmd := exec.CommandContext(
		ctx,
		ffprobeBinary,
		"-v", "error",
		"-print_format", "json",
		"-show_entries", "format=duration:stream=codec_type,duration",
		"-i", "pipe:0",
	)

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return 0, fmt.Errorf("ffprobe stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("ffprobe stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("ffprobe start: %w", err)
	}

	reader := file.NewReader()
	reader.SetResponsive()
	reader.SetReadahead(videoStreamReadaheadBytes)
	defer func() {
		if closer, ok := reader.(io.Closer); ok {
			closer.Close()
		}
	}()

	copyDone := make(chan struct{})
	var copyErr error
	go func() {
		defer close(copyDone)
		_, copyErr = io.Copy(stdinPipe, io.LimitReader(reader, transcodeDurationProbeMaxBytes))
		_ = stdinPipe.Close()
	}()

	ffprobeOutput, readErr := io.ReadAll(stdoutPipe)
	<-copyDone
	waitErr := cmd.Wait()

	if readErr != nil && !errors.Is(readErr, context.Canceled) {
		return 0, fmt.Errorf("ffprobe read output: %w", readErr)
	}
	if waitErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return 0, fmt.Errorf("ffprobe timeout after %s", transcodeDurationProbeTimeout)
		}
		return 0, fmt.Errorf("ffprobe wait: %w stderr=%q", waitErr, strings.TrimSpace(stderr.String()))
	}
	if copyErr != nil &&
		!errors.Is(copyErr, context.Canceled) &&
		!errors.Is(copyErr, io.ErrClosedPipe) &&
		!errors.Is(copyErr, syscall.EPIPE) {
		log.Printf(
			"[torrent-handler] req=%s transcode duration probe input copy warning session=%s file_index=%d file=%q err=%v",
			reqID,
			sessionID,
			fileIndex,
			fileName,
			copyErr,
		)
	}

	durationSeconds := extractDurationFromFFprobePayload(ffprobeOutput)
	if durationSeconds <= 0 {
		return 0, fmt.Errorf("duration unavailable")
	}
	return durationSeconds, nil
}

type transcodeDurationHintEntry struct {
	DurationSeconds float64
	CheckedAt       time.Time
}

func transcodeDurationHintCacheKey(sessionID string, fileIndex int) string {
	return sessionID + ":" + strconv.Itoa(fileIndex)
}

func resolveTranscodeDurationHint(
	reqID string,
	sessionID string,
	fileIndex int,
	file *torrent.File,
	fileName string,
	syncProbe bool,
) float64 {
	cacheKey := transcodeDurationHintCacheKey(sessionID, fileIndex)
	now := time.Now()

	if cached, ok := transcodeDurationHints.Load(cacheKey); ok {
		entry := cached.(transcodeDurationHintEntry)
		if entry.DurationSeconds > 0 {
			return entry.DurationSeconds
		}
		if now.Sub(entry.CheckedAt) < transcodeDurationProbeRetryDelay {
			return 0
		}
	}

	probeAndStore := func() float64 {
		startedAt := time.Now()
		durationSeconds, err := probeVideoDurationSeconds(reqID, sessionID, fileIndex, file, fileName)
		if err != nil {
			log.Printf(
				"[torrent-handler] req=%s transcode duration probe failed session=%s file_index=%d file=%q err=%v",
				reqID,
				sessionID,
				fileIndex,
				fileName,
				err,
			)
			transcodeDurationHints.Store(cacheKey, transcodeDurationHintEntry{
				DurationSeconds: 0,
				CheckedAt:       time.Now(),
			})
			return 0
		}

		transcodeDurationHints.Store(cacheKey, transcodeDurationHintEntry{
			DurationSeconds: durationSeconds,
			CheckedAt:       time.Now(),
		})

		log.Printf(
			"[torrent-handler] req=%s transcode duration probe success session=%s file_index=%d file=%q duration_seconds=%.3f elapsed_ms=%d",
			reqID,
			sessionID,
			fileIndex,
			fileName,
			durationSeconds,
			time.Since(startedAt).Milliseconds(),
		)
		return durationSeconds
	}

	if syncProbe {
		return probeAndStore()
	}

	if _, loaded := transcodeDurationProbes.LoadOrStore(cacheKey, struct{}{}); !loaded {
		go func() {
			defer transcodeDurationProbes.Delete(cacheKey)
			probeAndStore()
		}()
	}
	return 0
}

func streamTranscodedVideo(
	w http.ResponseWriter,
	r *http.Request,
	reqID string,
	sessionID string,
	fileIndex int,
	file *torrent.File,
	fileName string,
	startSeconds float64,
	durationHintSeconds float64,
) {
	ffmpegBinary := resolveFFmpegBinary()
	if _, err := exec.LookPath(ffmpegBinary); err != nil {
		log.Printf("[torrent-handler] req=%s transcode unavailable ffmpeg=%q err=%v", reqID, ffmpegBinary, err)
		respondWithJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "Compatibility transcoding is unavailable: ffmpeg is not installed",
		})
		return
	}

	w.Header().Set("Content-Type", "video/mp4")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Accept-Ranges", "none")
	w.Header().Set("X-BitPlay-Transcode", "ffmpeg")
	w.Header().Set("X-BitPlay-Reader-Mode", "responsive")
	w.Header().Set("X-BitPlay-Stream-Readahead", strconv.FormatInt(videoStreamReadaheadBytes, 10))
	if durationHintSeconds > 0 {
		w.Header().Set("X-BitPlay-Duration-Seconds", fmt.Sprintf("%.3f", durationHintSeconds))
	}

	if r.Method == http.MethodHead {
		return
	}

	args := []string{
		"-hide_banner",
		"-loglevel", "error",
		"-nostdin",
		"-fflags", "+genpts+nobuffer",
		"-analyzeduration", "2M",
		"-probesize", "2M",
	}

	inputMode := "pipe"
	inputTarget := "pipe:0"
	usePipeInput := true
	x264Params := "keyint=48:min-keyint=48:scenecut=0"
	movflags := "frag_keyframe+empty_moov+default_base_moof"
	videoRateArgs := []string{}
	inputSeekSeconds := 0.0
	outputSeekSeconds := 0.0

	if startSeconds > 0 {
		inputMode = "http-seekable-stream"
		usePipeInput = false
		inputTarget = fmt.Sprintf(
			"http://127.0.0.1:3347/api/v1/torrent/%s/stream/%d",
			sessionID,
			fileIndex,
		)

		// Prefer compatibility-oriented flags for seek restarts on embedded browsers.
		args[5] = "+genpts"
		x264Params = "keyint=24:min-keyint=24:scenecut=0:bframes=0:repeat-headers=1:aud=1"
		movflags = "frag_keyframe+empty_moov+default_base_moof"
		// Keep seek restarts decoder-friendly on low-power TV browsers.
		videoRateArgs = []string{"-b:v", "4M", "-maxrate", "4M", "-bufsize", "8M"}
		outputSeekSeconds = 8.0
		if startSeconds < outputSeekSeconds {
			outputSeekSeconds = startSeconds
		}
		inputSeekSeconds = startSeconds - outputSeekSeconds

		args = append(args, "-ss", fmt.Sprintf("%.3f", inputSeekSeconds))
		if authHeader := resolveInternalBasicAuthHeader(); authHeader != "" {
			args = append(args, "-headers", authHeader)
		}
		args = append(args,
			"-rw_timeout", "20000000",
			"-seekable", "1",
			"-i", inputTarget,
		)
	} else {
		args = append(args, "-i", inputTarget)
	}
	if outputSeekSeconds > 0 {
		args = append(args, "-ss", fmt.Sprintf("%.3f", outputSeekSeconds))
	}

	args = append(args,
		"-map", "0:v:0",
		"-map", "0:a:0?",
		"-c:v", "libx264",
		"-preset", "veryfast",
		"-tune", "zerolatency",
		"-profile:v", "main",
		"-level", "4.0",
	)
	args = append(args, videoRateArgs...)
	args = append(args,
		"-x264-params", x264Params,
		"-pix_fmt", "yuv420p",
		"-c:a", "aac",
		"-ac", "2",
		"-b:a", "160k",
		"-max_interleave_delta", "0",
		"-muxdelay", "0",
		"-muxpreload", "0",
		"-movflags", movflags,
		"-f", "mp4",
		"pipe:1",
	)

	log.Printf(
		"[torrent-handler] req=%s transcode start session=%s file_index=%d file=%q start_seconds=%.3f input_seek_seconds=%.3f output_seek_seconds=%.3f ffmpeg=%q args=%q",
		reqID,
		sessionID,
		fileIndex,
		fileName,
		startSeconds,
		inputSeekSeconds,
		outputSeekSeconds,
		ffmpegBinary,
		strings.Join(sanitizeFFmpegArgs(args), " "),
	)

	cmd := exec.CommandContext(r.Context(), ffmpegBinary, args...)

	var reader io.Reader
	var readerCloser io.Closer
	var stdinPipe io.WriteCloser
	var err error
	if usePipeInput {
		fileReader := file.NewReader()
		fileReader.SetResponsive()
		fileReader.SetReadahead(videoStreamReadaheadBytes)
		reader = fileReader
		if closer, ok := any(fileReader).(io.Closer); ok {
			readerCloser = closer
		}
		stdinPipe, err = cmd.StdinPipe()
		if err != nil {
			if readerCloser != nil {
				readerCloser.Close()
			}
			log.Printf("[torrent-handler] req=%s transcode stdin pipe error: %v", reqID, err)
			http.Error(w, "Failed to initialize transcoder input", http.StatusInternalServerError)
			return
		}
		defer func() {
			if readerCloser != nil {
				readerCloser.Close()
			}
		}()
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[torrent-handler] req=%s transcode stdout pipe error: %v", reqID, err)
		http.Error(w, "Failed to initialize transcoder output", http.StatusInternalServerError)
		return
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		log.Printf("[torrent-handler] req=%s transcode start error: %v", reqID, err)
		http.Error(w, "Failed to start transcoder", http.StatusBadGateway)
		return
	}

	copyInputDone := make(chan struct{})
	var copyInputErr error
	if usePipeInput {
		go func() {
			defer close(copyInputDone)
			_, copyInputErr = io.Copy(stdinPipe, reader)
			_ = stdinPipe.Close()
		}()
	} else {
		close(copyInputDone)
	}

	_, copyOutputErr := io.Copy(w, stdoutPipe)
	<-copyInputDone
	waitErr := cmd.Wait()

	if usePipeInput && copyInputErr != nil && !errors.Is(copyInputErr, context.Canceled) {
		log.Printf("[torrent-handler] req=%s transcode input copy error mode=%s: %v", reqID, inputMode, copyInputErr)
	}

	if copyOutputErr != nil && !errors.Is(copyOutputErr, context.Canceled) {
		log.Printf("[torrent-handler] req=%s transcode output copy error mode=%s: %v", reqID, inputMode, copyOutputErr)
	}

	if waitErr != nil && !errors.Is(waitErr, context.Canceled) {
		log.Printf(
			"[torrent-handler] req=%s transcode process error mode=%s input=%q: %v stderr=%q",
			reqID,
			inputMode,
			inputTarget,
			waitErr,
			strings.TrimSpace(stderr.String()),
		)
		return
	}

	log.Printf(
		"[torrent-handler] req=%s transcode complete session=%s file_index=%d file=%q",
		reqID,
		sessionID,
		fileIndex,
		fileName,
	)
}

func loadDotEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		line = strings.TrimPrefix(line, "export ")
		line = strings.TrimSpace(line)

		separator := strings.Index(line, "=")
		if separator <= 0 {
			log.Printf("Skipping malformed .env line %d", lineNumber)
			continue
		}

		key := strings.TrimSpace(line[:separator])
		if key == "" {
			log.Printf("Skipping malformed .env line %d", lineNumber)
			continue
		}

		value := strings.TrimSpace(line[separator+1:])
		quoted := len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\''))
		if quoted {
			value = value[1 : len(value)-1]
		} else {
			if commentIndex := strings.Index(value, " #"); commentIndex >= 0 {
				value = strings.TrimSpace(value[:commentIndex])
			}
		}

		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("failed to set env var %q from .env: %w", key, err)
		}
	}

	return scanner.Err()
}

func loadBasicAuthConfig() BasicAuthConfig {
	username := os.Getenv("BITPLAY_AUTH_USERNAME")
	password := os.Getenv("BITPLAY_AUTH_PASSWORD")

	if username == "" && password == "" {
		log.Println("HTTP basic auth is disabled (BITPLAY_AUTH_USERNAME/BITPLAY_AUTH_PASSWORD are not set).")
		return BasicAuthConfig{}
	}

	if username == "" || password == "" {
		log.Fatal("Both BITPLAY_AUTH_USERNAME and BITPLAY_AUTH_PASSWORD must be set to enable auth.")
	}

	realm := os.Getenv("BITPLAY_AUTH_REALM")
	if strings.TrimSpace(realm) == "" {
		realm = "BitPlay"
	}

	log.Printf("HTTP basic auth is enabled for realm %q", realm)
	return BasicAuthConfig{
		Enabled:  true,
		Username: username,
		Password: password,
		Realm:    realm,
	}
}

func secureStringEqual(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}

func withBasicAuth(next http.Handler, cfg BasicAuthConfig) http.Handler {
	if !cfg.Enabled {
		return next
	}

	challenge := fmt.Sprintf(`Basic realm=%q, charset="UTF-8"`, cfg.Realm)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || !secureStringEqual(username, cfg.Username) || !secureStringEqual(password, cfg.Password) {
			log.Printf(
				"[auth] unauthorized req=%s path=%s remote=%s user=%q",
				requestIDFromContext(r.Context()),
				r.URL.Path,
				r.RemoteAddr,
				username,
			)
			w.Header().Set("WWW-Authenticate", challenge)
			if strings.HasPrefix(r.URL.Path, "/api/") {
				respondWithJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
			} else {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

func withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := newRequestID()
		r = r.WithContext(context.WithValue(r.Context(), requestIDContextKey, reqID))
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w}
		lrw.Header().Set("X-Request-Id", reqID)

		next.ServeHTTP(lrw, r)

		if lrw.statusCode == 0 {
			lrw.statusCode = http.StatusOK
		}

		userAgent := r.UserAgent()
		if len(userAgent) > 180 {
			userAgent = userAgent[:180] + "..."
		}

		log.Printf(
			"[http] req=%s method=%s path=%s status=%d bytes=%d dur_ms=%d remote=%s range=%q referer=%q ua=%q",
			reqID,
			r.Method,
			r.URL.Path,
			lrw.statusCode,
			lrw.bytes,
			time.Since(start).Milliseconds(),
			r.RemoteAddr,
			r.Header.Get("Range"),
			r.Referer(),
			userAgent,
		)
	})
}

func main() {
	// Seed random number generator
	rand.Seed(time.Now().UnixNano())

	if err := loadDotEnvFile(".env"); err != nil {
		log.Printf("Warning: failed to load .env file: %v", err)
	}

	// Force proxy for all Go HTTP connections
	setGlobalProxy()

	if err := initTorrentStore("config/torrents.db"); err != nil {
		log.Fatalf("Failed to initialize torrent store: %v", err)
	}
	defer torrentDB.Close()

	authConfig := loadBasicAuthConfig()

	appMux := http.NewServeMux()

	// Set up endpoint handlers
	appMux.HandleFunc("/api/v1/torrent/add", addTorrentHandler)
	appMux.HandleFunc("/api/v1/torrent/", torrentHandler)
	appMux.HandleFunc("/api/v1/torrents", listSavedTorrentsHandler)
	appMux.HandleFunc("/api/v1/player-diagnostics", playerDiagnosticsHandler)
	appMux.HandleFunc("/api/v1/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			settingsMutex.RLock()
			defer settingsMutex.RUnlock()
			respondWithJSON(w, http.StatusOK, currentSettings)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	appMux.HandleFunc("/api/v1/settings/proxy", saveProxySettingsHandler)
	appMux.HandleFunc("/api/v1/settings/prowlarr", saveProwlarrSettingsHandler)
	appMux.HandleFunc("/api/v1/settings/jackett", saveJackettSettingsHandler)
	appMux.HandleFunc("/api/v1/prowlarr/search", searchFromProwlarr)
	appMux.HandleFunc("/api/v1/jackett/search", searchFromJackett)
	appMux.HandleFunc("/api/v1/prowlarr/test", testProwlarrConnection)
	appMux.HandleFunc("/api/v1/jackett/test", testJackettConnection)
	appMux.HandleFunc("/api/v1/proxy/test", testProxyConnection)
	appMux.HandleFunc("/api/v1/torrent/convert", convertTorrentToMagnetHandler)

	// Set up client file serving
	appMux.Handle("/", http.FileServer(http.Dir("./client")))
	appMux.HandleFunc("/client/", func(w http.ResponseWriter, r *http.Request) {
		http.StripPrefix("/client/", http.FileServer(http.Dir("./client"))).ServeHTTP(w, r)
	})
	appMux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./client/favicon.ico")
	})

	go cleanupSessions()

	port := 3347

	addr := fmt.Sprintf(":%d", port)
	log.Printf("Attempting to start server on %s", addr)

	// Create channel to signal if server started successfully
	serverStarted := make(chan bool, 1)

	// Create a server with graceful shutdown
	server := &http.Server{
		Addr:    addr,
		Handler: withRequestLogging(withBasicAuth(appMux, authConfig)),
	}

	// Start the server in a goroutine
	go func() {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Printf("Server failed on %s: %v", addr, err)
			serverStarted <- false
		}
	}()

	// Give the server a moment to start or fail
	select {
	case success := <-serverStarted:
		if !success {
			log.Printf("Server failed to start on %s", addr)
			return
		}
	case <-time.After(1 * time.Second):
		// No immediate error, assume it started successfully
		log.Printf("🚀 Server successfully started on %s", addr)

		// Create a simple message to display in the browser
		fmt.Printf("\n------------------------------------------------\n")
		fmt.Printf("✅ Server started! Open in your browser:\n")
		fmt.Printf("   http://localhost:%d\n", port)
		fmt.Printf("------------------------------------------------\n\n")

		// Block forever (the server is running in a goroutine)
		select {}
	}
}

// Set up global proxy for all Go HTTP calls
func setGlobalProxy() {
	settingsMutex.RLock()
	enableProxy := currentSettings.EnableProxy
	proxyURL := currentSettings.ProxyURL
	settingsMutex.RUnlock()

	if !enableProxy {
		log.Println("Proxy is disabled, not setting global HTTP proxy.")
		return
	}

	proxyDialer, err := createProxyDialer(proxyURL)
	if err != nil {
		log.Printf("Warning: Could not create proxy dialer: %v", err)
		return
	}

	httpTransport, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		httpTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return proxyDialer.Dial(network, addr)
		}
		log.Printf("Successfully configured SOCKS5 proxy for all HTTP traffic: %s", proxyURL)
	} else {
		log.Println("⚠️ Warning: Could not override HTTP transport")
	}
}

func resolveMagnetInput(input string) (string, error) {
	magnet := strings.TrimSpace(input)
	if magnet == "" {
		return "", errors.New("no magnet link provided")
	}

	// Handle HTTP links from search providers that redirect to magnet URIs.
	if strings.HasPrefix(strings.ToLower(magnet), "http") {
		httpClient := createSelectiveProxyClient()
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		req, err := http.NewRequest("GET", magnet, nil)
		if err != nil {
			return "", fmt.Errorf("invalid URL: %w", err)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to download: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := strings.TrimSpace(resp.Header.Get("Location"))
			if strings.HasPrefix(strings.ToLower(location), "magnet:") {
				magnet = location
			} else {
				return "", errors.New("URL redirects to non-magnet content")
			}
		}
	}

	if !strings.HasPrefix(strings.ToLower(magnet), "magnet:") {
		return "", errors.New("invalid magnet link")
	}
	return magnet, nil
}

func waitForTorrentInfo(t *torrent.Torrent, timeout time.Duration) error {
	select {
	case <-t.GotInfo():
		return nil
	case <-time.After(timeout):
		return errors.New("timeout getting info - proxy might be blocking BitTorrent traffic")
	}
}

func createSessionFromMagnet(magnet string) (string, error) {
	log.Printf("[torrent-session] create from magnet start hash=%s", extractInfoHashFromMagnet(magnet))
	client, port, err := initTorrentWithProxy()
	if err != nil {
		return "", fmt.Errorf("failed to create client with proxy: %w", err)
	}

	defer func() {
		if client != nil {
			releasePort(port)
			client.Close()
		}
	}()

	t, err := client.AddMagnet(magnet)
	if err != nil {
		return "", fmt.Errorf("invalid magnet url: %w", err)
	}
	log.Printf("[torrent-session] magnet added pending info hash=%s", t.InfoHash().HexString())

	if err := waitForTorrentInfo(t, 3*time.Minute); err != nil {
		log.Printf("[torrent-session] got-info timeout/failure hash=%s err=%v", t.InfoHash().HexString(), err)
		return "", err
	}

	sessionID := normalizeTorrentID(t.InfoHash().HexString())
	sessions.Store(sessionID, &TorrentSession{
		Client:   client,
		Torrent:  t,
		Port:     port,
		LastUsed: time.Now(),
	})
	client = nil

	record := buildStoredTorrentFromSession(sessionID, magnet, t)
	if err := storeTorrentRecord(record); err != nil {
		log.Printf("Warning: failed to persist torrent %s: %v", sessionID, err)
	}
	log.Printf("[torrent-session] created from magnet session=%s files=%d", sessionID, len(t.Files()))

	return sessionID, nil
}

func createSessionFromRecord(record *StoredTorrent) (string, error) {
	log.Printf(
		"[torrent-session] restore from record start id=%s has_metainfo=%t files_cached=%d",
		record.ID,
		len(record.MetaInfo) > 0,
		len(record.Files),
	)
	client, port, err := initTorrentWithProxy()
	if err != nil {
		return "", fmt.Errorf("failed to create client with proxy: %w", err)
	}

	defer func() {
		if client != nil {
			releasePort(port)
			client.Close()
		}
	}()

	var t *torrent.Torrent
	if len(record.MetaInfo) > 0 {
		if mi, err := metainfo.Load(bytes.NewReader(record.MetaInfo)); err == nil {
			t, err = client.AddTorrent(mi)
			if err != nil {
				log.Printf("Warning: failed to add torrent from cached metainfo for %s: %v", record.ID, err)
			} else {
				log.Printf("[torrent-session] restored via cached metainfo id=%s", record.ID)
			}
		} else {
			log.Printf("Warning: failed to parse cached metainfo for %s: %v", record.ID, err)
		}
	}

	if t == nil {
		if record.Magnet == "" {
			return "", errors.New("stored torrent has no magnet link")
		}
		t, err = client.AddMagnet(record.Magnet)
		if err != nil {
			return "", fmt.Errorf("failed to restore magnet session: %w", err)
		}
		log.Printf("[torrent-session] fallback restored via magnet id=%s", record.ID)
	}

	if err := waitForTorrentInfo(t, 3*time.Minute); err != nil {
		log.Printf("[torrent-session] restore got-info timeout/failure id=%s err=%v", record.ID, err)
		return "", err
	}

	sessionID := normalizeTorrentID(t.InfoHash().HexString())
	sessions.Store(sessionID, &TorrentSession{
		Client:   client,
		Torrent:  t,
		Port:     port,
		LastUsed: time.Now(),
	})
	client = nil

	updatedRecord := buildStoredTorrentFromSession(sessionID, record.Magnet, t)
	updatedRecord.AddedAt = record.AddedAt
	if err := storeTorrentRecord(updatedRecord); err != nil {
		log.Printf("Warning: failed to refresh stored torrent %s: %v", sessionID, err)
	}
	log.Printf("[torrent-session] restore done id=%s files=%d", sessionID, len(t.Files()))

	return sessionID, nil
}

func ensureTorrentSession(sessionID string) (*TorrentSession, error) {
	sessionID = normalizeTorrentID(sessionID)
	if sessionID == "" {
		return nil, errors.New("empty torrent id")
	}

	if value, ok := sessions.Load(sessionID); ok {
		session := value.(*TorrentSession)
		session.LastUsed = time.Now()
		markStoredTorrentUsed(sessionID)
		log.Printf("[torrent-session] cache hit id=%s", sessionID)
		return session, nil
	}
	log.Printf("[torrent-session] cache miss id=%s; trying persistent store", sessionID)

	record, err := getStoredTorrent(sessionID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		inMemorySummary := summarizeIDs(inMemorySessionIDs(), 8)
		storedIDs, storedErr := storedTorrentIDs()
		storedSummary := summarizeIDs(storedIDs, 8)
		if storedErr != nil {
			storedSummary = fmt.Sprintf("error loading stored ids: %v", storedErr)
		}
		log.Printf(
			"[torrent-session] not found in persistent store id=%s known_in_memory=%s known_stored=%s",
			sessionID,
			inMemorySummary,
			storedSummary,
		)
		return nil, errors.New("torrent not found")
	}

	restoredID, err := createSessionFromRecord(record)
	if err != nil {
		return nil, err
	}
	if restoredID != sessionID {
		log.Printf("[torrent-session] restore id mismatch requested=%s restored=%s", sessionID, restoredID)
	}

	value, ok := sessions.Load(restoredID)
	if !ok {
		return nil, errors.New("failed to create torrent session")
	}

	session := value.(*TorrentSession)
	session.LastUsed = time.Now()
	markStoredTorrentUsed(restoredID)
	log.Printf("[torrent-session] restored into memory id=%s", restoredID)
	return session, nil
}

func getOrCreateSessionByMagnet(magnet string) (string, error) {
	if infoHash := extractInfoHashFromMagnet(magnet); infoHash != "" {
		if value, ok := sessions.Load(infoHash); ok {
			session := value.(*TorrentSession)
			session.LastUsed = time.Now()
			markStoredTorrentUsed(infoHash)
			log.Printf("[torrent-session] reuse in-memory by magnet hash=%s", infoHash)
			return infoHash, nil
		}

		record, err := getStoredTorrent(infoHash)
		if err != nil {
			return "", err
		}
		if record != nil {
			log.Printf("[torrent-session] reuse persistent by magnet hash=%s", infoHash)
			return createSessionFromRecord(record)
		}
		log.Printf("[torrent-session] no cached entry for magnet hash=%s; creating new", infoHash)
	}

	log.Printf("[torrent-session] create new session (no parsed hash)")
	return createSessionFromMagnet(magnet)
}

func listSavedTorrentsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reqID := requestIDFromContext(r.Context())

	records, err := listStoredTorrents()
	if err != nil {
		log.Printf("[saved-torrents] req=%s list error=%v", reqID, err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to list stored torrents"})
		return
	}
	log.Printf("[saved-torrents] req=%s count=%d ids=%s", reqID, len(records), summarizeIDs(extractStoredTorrentIDs(records), 8))

	response := make([]StoredTorrentView, 0, len(records))
	for _, record := range records {
		response = append(response, toStoredTorrentView(record))
	}

	respondWithJSON(w, http.StatusOK, response)
}

func playerDiagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	reqID := requestIDFromContext(r.Context())
	logPath := resolvePlayerDiagnosticsLogPath()

	switch r.Method {
	case http.MethodPost:
		bodyReader := io.LimitReader(r.Body, maxPlayerDiagnosticsPayloadBytes)
		var payload map[string]interface{}
		if err := json.NewDecoder(bodyReader).Decode(&payload); err != nil {
			log.Printf("[player-diagnostics] req=%s decode error=%v", reqID, err)
			respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid diagnostics payload"})
			return
		}

		sessionID := ""
		if rawSessionID, ok := payload["sessionId"].(string); ok {
			sessionID = normalizeTorrentID(rawSessionID)
		}
		payload["sessionId"] = sessionID
		payload["serverReceivedAt"] = time.Now().UTC().Format(time.RFC3339Nano)
		payload["requestId"] = reqID
		payload["remoteAddr"] = r.RemoteAddr
		if _, exists := payload["userAgent"]; !exists {
			payload["userAgent"] = r.UserAgent()
		}

		line, err := json.Marshal(payload)
		if err != nil {
			log.Printf("[player-diagnostics] req=%s marshal error=%v", reqID, err)
			respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to encode diagnostics payload"})
			return
		}

		if err := appendPlayerDiagnosticsLine(logPath, line); err != nil {
			log.Printf("[player-diagnostics] req=%s append error path=%s err=%v", reqID, logPath, err)
			respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to store diagnostics payload"})
			return
		}

		log.Printf(
			"[player-diagnostics] req=%s stored path=%s session=%s bytes=%d kind=%v reason=%v",
			reqID,
			logPath,
			sessionID,
			len(line),
			payload["kind"],
			payload["reason"],
		)
		respondWithJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return

	case http.MethodGet:
		limit := defaultPlayerDiagnosticsReadLimit
		if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
			parsedLimit, err := strconv.Atoi(rawLimit)
			if err != nil {
				respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid 'limit' query parameter"})
				return
			}
			limit = parsedLimit
		}

		if limit < 1 {
			limit = 1
		}
		if limit > maxPlayerDiagnosticsReadLimit {
			limit = maxPlayerDiagnosticsReadLimit
		}

		sessionFilter := normalizeTorrentID(r.URL.Query().Get("sessionId"))
		lines, err := readRecentPlayerDiagnosticsLines(logPath, limit, sessionFilter)
		if err != nil {
			log.Printf("[player-diagnostics] req=%s read error path=%s err=%v", reqID, logPath, err)
			respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read diagnostics log"})
			return
		}

		log.Printf(
			"[player-diagnostics] req=%s read path=%s lines=%d filter_session=%q",
			reqID,
			logPath,
			len(lines),
			sessionFilter,
		)

		if strings.EqualFold(r.URL.Query().Get("format"), "json") {
			respondWithJSON(w, http.StatusOK, map[string]interface{}{
				"logPath":   logPath,
				"limit":     limit,
				"sessionId": sessionFilter,
				"count":     len(lines),
				"lines":     lines,
			})
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Player-Diagnostics-Log-Path", logPath)
		if len(lines) == 0 {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write([]byte(strings.Join(lines, "\n")))
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// Handler to add a torrent using a magnet link
func addTorrentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reqID := requestIDFromContext(r.Context())
	log.Printf("[add-torrent] req=%s request remote=%s ua=%q", reqID, r.RemoteAddr, r.UserAgent())

	var request struct {
		Magnet string `json:"magnet"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	magnet, err := resolveMagnetInput(request.Magnet)
	if err != nil {
		log.Printf("[add-torrent] req=%s resolve magnet failed err=%v", reqID, err)
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	log.Printf("[add-torrent] req=%s resolved magnet hash=%s", reqID, extractInfoHashFromMagnet(magnet))

	sessionID, err := getOrCreateSessionByMagnet(magnet)
	if err != nil {
		if strings.Contains(err.Error(), "timeout getting info") {
			log.Printf("[add-torrent] req=%s timeout while preparing session err=%v", reqID, err)
			respondWithJSON(w, http.StatusGatewayTimeout, map[string]string{"error": err.Error()})
			return
		}
		if strings.Contains(err.Error(), "invalid magnet") {
			log.Printf("[add-torrent] req=%s invalid magnet err=%v", reqID, err)
			respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid magnet url"})
			return
		}
		log.Printf("[add-torrent] req=%s create session error: %v", reqID, err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create torrent session"})
		return
	}

	markStoredTorrentUsed(sessionID)
	log.Printf("[add-torrent] req=%s session ready id=%s", reqID, sessionID)
	respondWithJSON(w, http.StatusOK, map[string]string{"sessionId": sessionID})
}

// Torrent handler to serve torrent files and stream content
func torrentHandler(w http.ResponseWriter, r *http.Request) {
	reqID := requestIDFromContext(r.Context())
	parts := strings.Split(r.URL.Path, "/")
	log.Printf(
		"[torrent-handler] req=%s request path=%s query=%q remote=%s range=%q ua=%q",
		reqID,
		r.URL.Path,
		r.URL.RawQuery,
		r.RemoteAddr,
		r.Header.Get("Range"),
		r.UserAgent(),
	)
	if len(parts) < 5 {
		log.Printf("[torrent-handler] req=%s invalid path parts=%v", reqID, parts)
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid path"})
		return
	}

	sessionID := normalizeTorrentID(parts[4])
	session, err := ensureTorrentSession(sessionID)
	if err != nil {
		log.Printf("[torrent-handler] req=%s session unavailable id=%s err=%v", reqID, sessionID, err)
		respondWithJSON(w, http.StatusNotFound, map[string]string{
			"error": "Torrent not found",
			"id":    sessionID,
		})
		return
	}

	if len(parts) > 5 && parts[5] == "diagnostics" {
		if r.Method != http.MethodGet {
			log.Printf("[torrent-handler] req=%s diagnostics unsupported method=%s", reqID, r.Method)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if len(parts) != 6 {
			log.Printf("[torrent-handler] req=%s invalid diagnostics path parts=%v", reqID, parts)
			respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid diagnostics path"})
			return
		}

		diagnostics := buildTorrentDiagnostics(sessionID, session)
		log.Printf(
			"[torrent-handler] req=%s diagnostics session=%s peers_total=%d peers_active=%d progress=%.2f download_rate_bps=%.0f upload_rate_bps=%.0f",
			reqID,
			sessionID,
			diagnostics.TotalPeers,
			diagnostics.ActivePeers,
			diagnostics.Progress,
			diagnostics.DownloadRateBps,
			diagnostics.UploadRateBps,
		)
		respondWithJSON(w, http.StatusOK, diagnostics)
		return
	}

	if len(parts) > 5 && parts[5] == "transcode" {
		if len(parts) < 7 {
			log.Printf("[torrent-handler] req=%s invalid transcode path parts=%v", reqID, parts)
			http.Error(w, "Invalid transcode path", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			log.Printf("[torrent-handler] req=%s transcode unsupported method=%s", reqID, r.Method)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		fileIndex, err := parseFileIndex(parts[6], len(session.Torrent.Files()))
		if err != nil {
			log.Printf(
				"[torrent-handler] req=%s invalid transcode file index raw=%q max_files=%d err=%v",
				reqID,
				parts[6],
				len(session.Torrent.Files()),
				err,
			)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		startSeconds, err := parseStartSeconds(r.URL.Query().Get("start"))
		if err != nil {
			log.Printf(
				"[torrent-handler] req=%s invalid transcode start session=%s file_index=%d raw=%q err=%v",
				reqID,
				sessionID,
				fileIndex,
				r.URL.Query().Get("start"),
				err,
			)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		file := session.Torrent.Files()[fileIndex]
		fileName := file.DisplayPath()
		extension := strings.ToLower(filepath.Ext(fileName))
		if !isVideoExtension(extension) {
			log.Printf(
				"[torrent-handler] req=%s transcode unsupported extension session=%s file_index=%d ext=%s file=%q",
				reqID,
				sessionID,
				fileIndex,
				extension,
				fileName,
			)
			http.Error(w, "Unsupported file type for transcode", http.StatusBadRequest)
			return
		}

		file.SetPriority(torrent.PiecePriorityHigh)
		file.Download()
		progress := buildFileProgressSnapshot(file)
		log.Printf(
			"[torrent-handler] req=%s transcode prioritize session=%s file_index=%d priority=%d bytes_completed=%d file_completed_bytes=%d file_contiguous_bytes=%d file_total_bytes=%d file_pieces=%d/%d",
			reqID,
			sessionID,
			fileIndex,
			file.Priority(),
			file.BytesCompleted(),
			progress.CompletedBytes,
			progress.ContiguousBytes,
			progress.TotalBytes,
			progress.PiecesComplete,
			progress.PiecesTotal,
		)

		if r.Method == http.MethodGet {
			startupTargetBytes := int64(transcodeStartupMinContiguousBytes)
			if file.Length() > 0 && file.Length() < startupTargetBytes {
				startupTargetBytes = file.Length()
			}
			startupSnapshot := progress
			if startupTargetBytes > 0 && startupSnapshot.ContiguousBytes < startupTargetBytes {
				waitStartedAt := time.Now()
				deadline := waitStartedAt.Add(transcodeStartupWaitTimeout)
				waitReason := "timeout"

				for startupSnapshot.ContiguousBytes < startupTargetBytes {
					if r.Context().Err() != nil {
						waitReason = "canceled"
						break
					}
					if time.Now().After(deadline) {
						break
					}
					time.Sleep(transcodeStartupPollInterval)
					startupSnapshot = buildFileProgressSnapshot(file)
				}

				if startupSnapshot.ContiguousBytes >= startupTargetBytes {
					waitReason = "ready"
				}

				log.Printf(
					"[torrent-handler] req=%s transcode startup wait session=%s file_index=%d reason=%s waited_ms=%d target_contiguous_bytes=%d contiguous_bytes=%d completed_bytes=%d total_bytes=%d pieces=%d/%d",
					reqID,
					sessionID,
					fileIndex,
					waitReason,
					time.Since(waitStartedAt).Milliseconds(),
					startupTargetBytes,
					startupSnapshot.ContiguousBytes,
					startupSnapshot.CompletedBytes,
					startupSnapshot.TotalBytes,
					startupSnapshot.PiecesComplete,
					startupSnapshot.PiecesTotal,
				)
			}
		}

		durationHintSeconds := resolveTranscodeDurationHint(
			reqID,
			sessionID,
			fileIndex,
			file,
			fileName,
			r.Method == http.MethodHead,
		)

		streamTranscodedVideo(
			w,
			r,
			reqID,
			sessionID,
			fileIndex,
			file,
			fileName,
			startSeconds,
			durationHintSeconds,
		)
		return
	}

	// If there's a direct streaming request, handle it
	if len(parts) > 5 && parts[5] == "stream" {
		if len(parts) < 7 {
			log.Printf("[torrent-handler] req=%s invalid stream path parts=%v", reqID, parts)
			http.Error(w, "Invalid stream path", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			log.Printf("[torrent-handler] req=%s stream unsupported method=%s", reqID, r.Method)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		fileIndex, err := parseFileIndex(parts[6], len(session.Torrent.Files()))
		if err != nil {
			log.Printf(
				"[torrent-handler] req=%s invalid stream file index raw=%q max_files=%d err=%v",
				reqID,
				parts[6],
				len(session.Torrent.Files()),
				err,
			)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		file := session.Torrent.Files()[fileIndex]

		// Set appropriate Content-Type based on file extension
		fileName := file.DisplayPath()
		extension := strings.ToLower(filepath.Ext(fileName))
		isVideo := isVideoExtension(extension)

		if isVideo {
			file.SetPriority(torrent.PiecePriorityHigh)
			file.Download()
			progress := buildFileProgressSnapshot(file)
			log.Printf(
				"[torrent-handler] req=%s prioritize file session=%s file_index=%d priority=%d bytes_completed=%d file_completed_bytes=%d file_contiguous_bytes=%d file_total_bytes=%d file_pieces=%d/%d",
				reqID,
				sessionID,
				fileIndex,
				file.Priority(),
				file.BytesCompleted(),
				progress.CompletedBytes,
				progress.ContiguousBytes,
				progress.TotalBytes,
				progress.PiecesComplete,
				progress.PiecesTotal,
			)
		}

		log.Printf(
			"[torrent-handler] req=%s direct stream session=%s file_index=%d ext=%s size=%d file=%q method=%s range=%q",
			reqID,
			sessionID,
			fileIndex,
			extension,
			file.Length(),
			fileName,
			r.Method,
			r.Header.Get("Range"),
		)

		switch extension {
		case ".mp4":
			w.Header().Set("Content-Type", "video/mp4")
		case ".webm":
			w.Header().Set("Content-Type", "video/webm")
		case ".mkv":
			w.Header().Set("Content-Type", "video/x-matroska")
		case ".avi":
			w.Header().Set("Content-Type", "video/x-msvideo")
		case ".srt":
			// For SRT, convert to VTT on-the-fly if requested as VTT
			if r.URL.Query().Get("format") == "vtt" {
				w.Header().Set("Content-Type", "text/vtt")
				w.Header().Set("Access-Control-Allow-Origin", "*")

				reader := file.NewReader()
				limitReader := io.LimitReader(reader, 10*1024*1024)
				srtBytes, err := io.ReadAll(limitReader)
				if err != nil {
					http.Error(w, "Failed to read subtitle file", http.StatusInternalServerError)
					return
				}

				vttBytes := convertSRTtoVTT(srtBytes)
				w.Write(vttBytes)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Access-Control-Allow-Origin", "*")
		case ".vtt":
			w.Header().Set("Content-Type", "text/vtt")
			w.Header().Set("Access-Control-Allow-Origin", "*")
		case ".sub":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Access-Control-Allow-Origin", "*")
		default:
			w.Header().Set("Content-Type", "application/octet-stream")
		}

		reader := file.NewReader()
		if isVideo {
			reader.SetResponsive()
			reader.SetReadahead(videoStreamReadaheadBytes)
			w.Header().Set("X-BitPlay-Stream-Readahead", strconv.FormatInt(videoStreamReadaheadBytes, 10))
			w.Header().Set("X-BitPlay-Reader-Mode", "responsive")
		}
		defer func() {
			if closer, ok := reader.(io.Closer); ok {
				closer.Close()
			}
		}()

		log.Printf(
			"[torrent-handler] req=%s servecontent session=%s file_index=%d content_type=%q",
			reqID,
			sessionID,
			fileIndex,
			w.Header().Get("Content-Type"),
		)
		http.ServeContent(w, r, fileName, time.Time{}, reader)
		return
	}

	if len(parts) > 5 {
		log.Printf("[torrent-handler] req=%s unsupported action=%q path=%s", reqID, parts[5], r.URL.Path)
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Unsupported torrent action"})
		return
	}

	files := make([]StoredTorrentFile, 0, len(session.Torrent.Files()))
	for i, file := range session.Torrent.Files() {
		files = append(files, StoredTorrentFile{
			Index: i,
			Name:  file.DisplayPath(),
			Size:  file.Length(),
		})
	}
	log.Printf("[torrent-handler] req=%s list files session=%s count=%d", reqID, sessionID, len(files))

	respondWithJSON(w, http.StatusOK, files)
}

// Add a function to convert SRT to VTT format
func convertSRTtoVTT(srtBytes []byte) []byte {
	srtContent := string(srtBytes)

	// Add VTT header
	vttContent := "WEBVTT\n\n"

	// Convert SRT content to VTT format
	// Simple conversion - replace timestamps format
	lines := strings.Split(srtContent, "\n")

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Skip subtitle numbers
		if _, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
			continue
		}

		// Convert timestamp lines
		if strings.Contains(line, " --> ") {
			// SRT: 00:00:20,000 --> 00:00:24,400
			// VTT: 00:00:20.000 --> 00:00:24.400
			line = strings.Replace(line, ",", ".", -1)
			vttContent += line + "\n"
		} else {
			vttContent += line + "\n"
		}
	}

	return []byte(vttContent)
}

// Helper function to respond with JSON
func respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Update cleanupSessions with safer reflection
func cleanupSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		log.Printf("Checking for unused sessions...")
		sessions.Range(func(key, value interface{}) bool {
			session := value.(*TorrentSession)

			if time.Since(session.LastUsed) > 15*time.Minute {
				releasePort(session.Port)
				session.Torrent.Drop()
				session.Client.Close()
				sessions.Delete(key)
				log.Printf("Removed unused session: %s", key)
			}
			return true
		})
		runtime.GC()
	}
}

// Test the proxy connection
func testProwlarrConnection(w http.ResponseWriter, r *http.Request) {
	// Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight requests
	if r.Method == "OPTIONS" {
		return
	}

	var settings ProwlarrSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	prowlarrHost := settings.ProwlarrHost
	prowlarrApiKey := settings.ProwlarrApiKey

	if prowlarrHost == "" || prowlarrApiKey == "" {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Prowlarr host or API key not set"})
		return
	}

	client := createSelectiveProxyClient()
	testURL := fmt.Sprintf("%s/api/v1/system/status", prowlarrHost)

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	req.Header.Set("X-Api-Key", prowlarrApiKey)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making request to Prowlarr: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to connect to Prowlarr: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respondWithJSON(w, resp.StatusCode, map[string]string{"error": fmt.Sprintf("Prowlarr returned status %d", resp.StatusCode)})
		return
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read Prowlarr response"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseBody)
}

// Search from Prowlarr
func searchFromProwlarr(w http.ResponseWriter, r *http.Request) {
	// Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Prowlarr-Host, X-Api-Key")

	// Handle preflight requests
	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "No search query provided"})
		return
	}

	// search movies in prowlarr
	settingsMutex.RLock()
	prowlarrHost := currentSettings.ProwlarrHost
	prowlarrApiKey := currentSettings.ProwlarrApiKey
	settingsMutex.RUnlock()

	if prowlarrHost == "" || prowlarrApiKey == "" {
		http.Error(w, "Prowlarr host or API key not set", http.StatusBadRequest)
		return
	}

	// Use the client that bypasses proxy for Prowlarr
	client := createSelectiveProxyClient()

	// Prowlarr search endpoint - looking for movie torrents
	searchURL := fmt.Sprintf("%s/api/v1/search?query=%s&limit=10", prowlarrHost, url.QueryEscape(query))

	req, err := http.NewRequest("GET", searchURL, nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	req.Header.Set("X-Api-Key", prowlarrApiKey)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making request to Prowlarr: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to connect to Prowlarr: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read Prowlarr response"})
		return
	}

	if resp.StatusCode != http.StatusOK {
		respondWithJSON(w, resp.StatusCode, map[string]string{"error": fmt.Sprintf("Prowlarr returned status %d: %s", resp.StatusCode, string(body))})
		return
	}

	// Parse the JSON response and process the results
	var results []map[string]interface{}
	if err := json.Unmarshal(body, &results); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to parse Prowlarr response"})
		return
	}

	// Process the results to make them more usable by the frontend
	var processedResults []map[string]interface{}
	for _, result := range results {
		// Get title and download URL
		title, hasTitle := result["title"].(string)
		downloadUrl, hasDownloadUrl := result["downloadUrl"].(string)

		// Magnet URL might be present in some results
		magnetUrl, hasMagnet := result["magnetUrl"].(string)

		if !hasTitle || title == "" {
			// Skip results without titles
			continue
		}

		// We need at least one of download URL or magnet URL
		if (!hasDownloadUrl || downloadUrl == "") && (!hasMagnet || magnetUrl == "") {
			continue
		}

		// Create a simplified result object with just what we need
		processedResult := map[string]interface{}{
			"title": title,
		}

		// Prefer magnet URLs if available directly
		if hasMagnet && magnetUrl != "" {
			processedResult["magnetUrl"] = magnetUrl
			processedResult["directMagnet"] = true
		} else if hasDownloadUrl && downloadUrl != "" {
			processedResult["downloadUrl"] = downloadUrl
			processedResult["directMagnet"] = false
		}

		// Include optional fields if they exist
		if size, ok := result["size"].(float64); ok {
			processedResult["size"] = formatSize(size)
		}

		if seeders, ok := result["seeders"].(float64); ok {
			processedResult["seeders"] = seeders
		}

		if leechers, ok := result["leechers"].(float64); ok {
			processedResult["leechers"] = leechers
		}

		if indexer, ok := result["indexer"].(string); ok {
			processedResult["indexer"] = indexer
		}

		if publishDate, ok := result["publishDate"].(string); ok {
			processedResult["publishDate"] = publishDate
		}

		if category, ok := result["category"].(string); ok {
			processedResult["category"] = category
		}

		processedResults = append(processedResults, processedResult)
	}

	respondWithJSON(w, http.StatusOK, processedResults)
}

// Test Jackett Connection Handler
func testJackettConnection(w http.ResponseWriter, r *http.Request) {
	// Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	// Handle preflight requests
	if r.Method == "OPTIONS" {
		return
	}

	var settings JackettSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	jackettHost := settings.JackettHost
	jackettApiKey := settings.JackettApiKey

	if jackettHost == "" || jackettApiKey == "" {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Jackett host or API key not set"})
		return
	}

	client := createSelectiveProxyClient()
	testURL := fmt.Sprintf("%s/api/v2.0/indexers/all/results?apikey=%s", jackettHost, jackettApiKey)
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making request to Jackett: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to connect to Jackett: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respondWithJSON(w, resp.StatusCode, map[string]string{"error": fmt.Sprintf("Jackett returned status %d", resp.StatusCode)})
		return
	}
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read Jackett response"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseBody)
}

// Search from Jackett
func searchFromJackett(w http.ResponseWriter, r *http.Request) {
	// Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight requests
	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "No search query provided"})
		return
	}

	// search movies in jackett
	settingsMutex.RLock()
	jackettHost := currentSettings.JackettHost
	jackettApiKey := currentSettings.JackettApiKey
	settingsMutex.RUnlock()

	if jackettHost == "" || jackettApiKey == "" {
		http.Error(w, "Jackett host or API key not set", http.StatusBadRequest)
		return
	}

	// Use the client that bypasses proxy for Jackett
	client := createSelectiveProxyClient()

	// Jackett search endpoint - looking for movie torrents
	searchURL := fmt.Sprintf("%s/api/v2.0/indexers/all/results?Query=%s&apikey=%s", jackettHost, url.QueryEscape(query), jackettApiKey)

	req, err := http.NewRequest("GET", searchURL, nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making request to Jackett: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to connect to Jackett: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read Jackett response"})
		return
	}

	if resp.StatusCode != http.StatusOK {
		respondWithJSON(w, resp.StatusCode, map[string]string{"error": fmt.Sprintf("Jackett returned status %d: %s", resp.StatusCode, string(body))})
		return
	}

	var jacketResponse struct {
		Results []map[string]interface{} `json:"Results"`
	}

	// Parse the JSON response and process the results
	if err := json.Unmarshal(body, &jacketResponse); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to parse Jackett response"})
		return
	}

	// Process the results to make them more usable by the frontend
	var processedResults []map[string]interface{}
	for _, result := range jacketResponse.Results {
		// Get title and download URL
		title, hasTitle := result["Title"].(string)
		downloadUrl, hasDownloadUrl := result["Link"].(string)

		// Magnet URL might be present in some results
		magnetUrl, hasMagnet := result["MagnetUri"].(string)

		if !hasTitle || title == "" {
			// Skip results without titles
			continue
		}

		// We need at least one of download URL or magnet URL
		if (!hasDownloadUrl || downloadUrl == "") && (!hasMagnet || magnetUrl == "") {
			continue
		}

		// Create a simplified result object with just what we need
		processedResult := map[string]interface{}{
			"title": title,
		}

		// Prefer magnet URLs if available directly
		if hasMagnet && magnetUrl != "" && strings.HasPrefix(magnetUrl, "magnet:") {
			processedResult["magnetUrl"] = magnetUrl
			processedResult["directMagnet"] = true
		} else if hasDownloadUrl && downloadUrl != "" {
			processedResult["downloadUrl"] = downloadUrl
			processedResult["directMagnet"] = false
		}

		// Include optional fields if they exist
		if size, ok := result["Size"].(float64); ok {
			processedResult["size"] = formatSize(size)
		}

		if seeders, ok := result["Seeders"].(float64); ok {
			processedResult["seeders"] = seeders
		}

		if leechers, ok := result["Peers"].(float64); ok {
			processedResult["leechers"] = leechers
		}

		if indexer, ok := result["Tracker"].(string); ok {
			processedResult["indexer"] = indexer
		}

		if publishDate, ok := result["PublishDate"].(string); ok {
			processedResult["publishDate"] = publishDate
		}

		if category, ok := result["category"].(string); ok {
			processedResult["category"] = category
		}

		processedResults = append(processedResults, processedResult)
	}

	respondWithJSON(w, http.StatusOK, processedResults)
}

// Test Proxy Connection Handler
func testProxyConnection(w http.ResponseWriter, r *http.Request) {
	// Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight requests
	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var settings ProxySettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	proxyURL := settings.ProxyURL

	if proxyURL == "" {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Proxy URL not set"})
		return
	}

	// Parse the proxy URL
	parsedProxyURL, err := url.Parse(proxyURL)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid proxy URL: " + err.Error()})
		return
	}

	// Create a transport that uses the proxy
	transport := &http.Transport{
		Proxy: http.ProxyURL(parsedProxyURL),
	}

	// Create client with custom transport and timeout
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second, // Adjust timeout as needed
	}

	testURL := "https://httpbin.org/ip"
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making request through proxy: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Proxy connection failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read proxy response"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseBody)
}

// Helper function to save settings to file (assumes mutex is already locked)
func saveSettingsToFile() error {
	// Create the directory if it doesn't exist
	if err := os.MkdirAll("config", 0755); err != nil {
		log.Fatalf("Failed to create config directory: %v", err)
	}

	file, err := os.Create("config/settings.json")
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(currentSettings); err != nil {
		return err
	}

	return nil
}

// Proxy Settings Save Handler
func saveProxySettingsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == "OPTIONS" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newSettings ProxySettings
	if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	settingsMutex.RLock()
	currentSettings.EnableProxy = newSettings.EnableProxy
	currentSettings.ProxyURL = newSettings.ProxyURL
	defer settingsMutex.RUnlock()

	if err := saveSettingsToFile(); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save settings: " + err.Error()})
		return
	}
	println("Proxy settings saved successfully")

	setGlobalProxy()

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "Proxy settings saved successfully"})
}

// Prowlarr Settings Save Handler
func saveProwlarrSettingsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == "OPTIONS" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newSettings ProwlarrSettings
	if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	settingsMutex.RLock()
	currentSettings.EnableProwlarr = newSettings.EnableProwlarr
	currentSettings.ProwlarrHost = newSettings.ProwlarrHost
	currentSettings.ProwlarrApiKey = newSettings.ProwlarrApiKey
	defer settingsMutex.RUnlock()

	if err := saveSettingsToFile(); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save settings: " + err.Error()})
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "Prowlarr settings saved successfully"})
}

// Jackett Settings Save Handler
func saveJackettSettingsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == "OPTIONS" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newSettings JackettSettings
	if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	settingsMutex.RLock()
	currentSettings.EnableJackett = newSettings.EnableJackett
	currentSettings.JackettHost = newSettings.JackettHost
	currentSettings.JackettApiKey = newSettings.JackettApiKey
	defer settingsMutex.RUnlock()

	if err := saveSettingsToFile(); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save settings: " + err.Error()})
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "Jackett settings saved successfully"})
}

// Convert Torrent to Magnet Handler
func convertTorrentToMagnetHandler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form with 10MB memory limit
	const maxUploadSize = 10 << 20 // 10MB
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Failed to parse form: " + err.Error()})
		return
	}

	// Get the torrent file from the form data
	file, header, err := r.FormFile("torrent")
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing torrent file"})
		return
	}
	defer file.Close()

	// Check file size
	if header.Size > maxUploadSize {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "File too large"})
		return
	}

	// Read the torrent file content
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read file"})
		return
	}

	// Parse torrent file
	mi, err := metainfo.Load(bytes.NewReader(fileBytes))
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid torrent file: " + err.Error()})
		return
	}

	// Get info hash
	infoHash := mi.HashInfoBytes().String()

	// Build magnet URL components
	magnet := fmt.Sprintf("magnet:?xt=urn:btih:%s", infoHash)

	// Add display name
	info, err := mi.UnmarshalInfo()
	if err == nil {
		magnet += fmt.Sprintf("&dn=%s", url.QueryEscape(info.Name))
	}

	// Add trackers
	for _, tier := range mi.AnnounceList {
		for _, tracker := range tier {
			magnet += fmt.Sprintf("&tr=%s", url.QueryEscape(tracker))
		}
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"magnet": magnet,
	})
}
