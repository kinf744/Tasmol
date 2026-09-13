package importExport

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"vpn-app/internal/config"
)

type Exporter struct {
	configManager *config.Manager
	password      string
}

type Importer struct {
	configManager *config.Manager
	password      string
}

func NewExporter(cm *config.Manager, password string) *Exporter {
	return &Exporter{
		configManager: cm,
		password:      password,
	}
}

func NewImporter(cm *config.Manager, password string) *Importer {
	return &Importer{
		configManager: cm,
		password:      password,
	}
}

func (e *Exporter) ExportToFile(path string) error {
	data, err := e.configManager.Export()
	if err != nil {
		return err
	}

	content, err := yaml.Marshal(data)
	if err != nil {
		return err
	}

	if e.password != "" {
		content, err = e.encrypt(content)
		if err != nil {
			return err
		}
	}

	return os.WriteFile(path, content, 0644)
}

func (e *Exporter) ExportToJSON(path string) error {
	data, err := e.configManager.Export()
	if err != nil {
		return err
	}

	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	if e.password != "" {
		content, err = e.encrypt(content)
		if err != nil {
			return err
		}
	}

	return os.WriteFile(path, content, 0644)
}

func (e *Exporter) ExportToZip(path string) error {
	data, err := e.configManager.Export()
	if err != nil {
		return err
	}

	content, err := yaml.Marshal(data)
	if err != nil {
		return err
	}

	if e.password != "" {
		content, err = e.encrypt(content)
		if err != nil {
			return err
		}
	}

	zipFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	writer, err := zipWriter.Create("vpn-config.yaml")
	if err != nil {
		return err
	}

	_, err = writer.Write(content)
	return err
}

func (i *Importer) ImportFromFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if i.password != "" {
		content, err = i.decrypt(content)
		if err != nil {
			return err
		}
	}

	if strings.HasSuffix(path, ".json") {
		return i.configManager.ImportJSON(content)
	}

	return i.configManager.ImportYAML(content)
}

func (i *Importer) ImportFromZip(path string) error {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer reader.Close()

	for _, file := range reader.File {
		if file.Name == "vpn-config.yaml" || file.Name == "vpn-config.json" {
			rc, err := file.Open()
			if err != nil {
				return err
			}
			defer rc.Close()

			content, err := io.ReadAll(rc)
			if err != nil {
				return err
			}

			if i.password != "" {
				content, err = i.decrypt(content)
				if err != nil {
					return err
				}
			}

			if strings.HasSuffix(file.Name, ".json") {
				return i.configManager.ImportJSON(content)
			}
			return i.configManager.ImportYAML(content)
		}
	}

	return fmt.Errorf("no config file found in zip")
}

func (e *Exporter) encrypt(data []byte) ([]byte, error) {
	key := sha256.Sum256([]byte(e.password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

func (i *Importer) decrypt(data []byte) ([]byte, error) {
	key := sha256.Sum256([]byte(i.password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(decoded) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := decoded[:nonceSize], decoded[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

type ExportInfo struct {
	Version     string    `json:"version"`
	ExportedAt  time.Time `json:"exported_at"`
	TunnelCount int       `json:"tunnel_count"`
	Encrypted   bool      `json:"encrypted"`
	Format      string    `json:"format"`
	Size        int64     `json:"size"`
}

func GetExportInfo(path string) (*ExportInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	encrypted := false
	format := "yaml"
	tunnelCount := 0

	if strings.HasSuffix(path, ".json") {
		format = "json"
		var data config.ExportData
		if err := json.Unmarshal(content, &data); err == nil {
			tunnelCount = len(data.Tunnels)
		}
	} else if strings.HasSuffix(path, ".zip") {
		format = "zip"
	} else {
		var data config.ExportData
		if err := yaml.Unmarshal(content, &data); err == nil {
			tunnelCount = len(data.Tunnels)
		}
	}

	if len(content) > 0 {
		_, err := base64.StdEncoding.DecodeString(string(content))
		encrypted = err == nil
	}

	return &ExportInfo{
		Version:     "1.0",
		ExportedAt:  time.Now(),
		TunnelCount: tunnelCount,
		Encrypted:   encrypted,
		Format:      format,
		Size:        info.Size(),
	}, nil
}

func ValidateExportFile(path string) error {
	info, err := GetExportInfo(path)
	if err != nil {
		return err
	}

	if info.TunnelCount == 0 {
		return fmt.Errorf("no tunnels found in export file")
	}

	return nil
}

func ListExportFiles(dir string) ([]ExportInfo, error) {
	files, err := filepath.Glob(filepath.Join(dir, "vpn-config.*"))
	if err != nil {
		return nil, err
	}

	result := make([]ExportInfo, 0, len(files))
	for _, file := range files {
		info, err := GetExportInfo(file)
		if err == nil {
			result = append(result, *info)
		}
	}

	return result, nil
}
