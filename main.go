package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
)


type Note struct {
	ID               int64
	Title            string
	EncryptedContent []byte
	Nonce            []byte 
	FilePath         string 
	CreatedAt        time.Time
	UpdatedAt        time.Time
}


type CryptoManager struct {
	privateKey kem.PrivateKey
	publicKey  kem.PublicKey
	sessionKey []byte    
	passHash   []byte
}

type AppState struct {
	db           *sql.DB
	notes        []Note
	cryptoMgr    *CryptoManager
	currentNote  *Note
	authenticated bool
	userID        int64
	dataDir       string
}

func showAboutDialog(win fyne.Window) {
	aboutContent := container.NewVBox(
		widget.NewLabel("Quantum Notes"),
		widget.NewLabel("Version 1.0.1"),
		widget.NewLabel(""),
		widget.NewLabel("Developed by Gaurav Kumar🚀"),
		widget.NewLabel("© 2025 All Rights Reserved"),
	)

	
	for _, obj := range aboutContent.Objects {
		if label, ok := obj.(*widget.Label); ok {
			label.Alignment = fyne.TextAlignCenter
			label.TextStyle = fyne.TextStyle{Bold: true}
		}
	}

	aboutDialog := dialog.NewCustom("About", "Close", aboutContent, win)
	aboutDialog.Resize(fyne.NewSize(300, 200))
	aboutDialog.Show()
}

func setupMainMenu(myWindow fyne.Window) {
	mainMenu := fyne.NewMainMenu(
		fyne.NewMenu("About",
			fyne.NewMenuItem("About Quantum Secure Notes", func() {
				showAboutDialog(myWindow)
			}),
		),
	)

	myWindow.SetMainMenu(mainMenu)
}


func main() {
	myApp := app.NewWithID("com.quantum.notes")
	iconPath := "icon.png"
	icon, err := fyne.LoadResourceFromPath(iconPath)
	if err != nil {
		
		if execPath, execErr := os.Executable(); execErr == nil {
			iconPath = filepath.Join(filepath.Dir(execPath), "icon.png")
			icon, err = fyne.LoadResourceFromPath(iconPath)
		}
	}

	if err == nil && icon != nil {
		myApp.SetIcon(icon)
	}

	myWindow := myApp.NewWindow("Quantum Notes")
	myWindow.Resize(fyne.NewSize(800, 600))
	
	setupMainMenu(myWindow)


	homeDir, err := os.UserHomeDir()
	if err != nil {
		dialog.ShowError(errors.New("Failed to determine user home directory"), myWindow)
		return
	}
	
	dataDir := filepath.Join(homeDir, ".quantum_secure_notes")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		dialog.ShowError(errors.New("Failed to create application data directory"), myWindow)
		return
	}

	state := &AppState{
		authenticated: false,
		dataDir:       dataDir,
	}

	// Initialize SQLite database
	db, err := initDB(dataDir)
	if err != nil {
		dialog.ShowError(err, myWindow)
		return
	}
	state.db = db
	defer db.Close()

	loginScreen(myWindow, state)

	myWindow.ShowAndRun()
}

func initDB(dataDir string) (*sql.DB, error) {
	dbPath := filepath.Join(dataDir, "quantum_notes.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash BLOB NOT NULL,
			salt BLOB NOT NULL,
			public_key BLOB NOT NULL,
			encrypted_private_key BLOB NOT NULL
		);
		CREATE TABLE IF NOT EXISTS notes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			encrypted_content BLOB NOT NULL,
			nonce BLOB NOT NULL,
			file_path TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users (id)
		);
	`)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func loginScreen(w fyne.Window, state *AppState) {
	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Username")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Password")

	loginBtn := widget.NewButton("Login", func() {
		username := usernameEntry.Text
		password := passwordEntry.Text

		if username == "" || password == "" {
			dialog.ShowInformation("Error", "Username and password are required", w)
			return
		}

		err := login(state, username, password)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}

		notesScreen(w, state)
	})

	registerBtn := widget.NewButton("Register", func() {
		username := usernameEntry.Text
		password := passwordEntry.Text

		if username == "" || password == "" {
			dialog.ShowInformation("Error", "Username and password are required", w)
			return
		}

		err := register(state, username, password)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}

		dialog.ShowInformation("Success", "Registration successful! You can now login.", w)
	})

	content := container.NewVBox(
		widget.NewLabel("Quantum Notes"),
		container.NewPadded(usernameEntry),
		container.NewPadded(passwordEntry),
		container.NewHBox(
			layout.NewSpacer(),
			loginBtn,
			registerBtn,
			layout.NewSpacer(),
		),
	)

	w.SetContent(container.NewCenter(content))
}

func notesScreen(w fyne.Window, state *AppState) {
	
	err := loadNotes(state)
	if err != nil {
		dialog.ShowError(err, w)
		return
	}

	notesList := widget.NewList(
		func() int { return len(state.notes) },
		func() fyne.CanvasObject { return widget.NewLabel("Note title") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			obj.(*widget.Label).SetText(state.notes[id].Title)
		},
	)

	titleEntry := widget.NewEntry()
	titleEntry.SetPlaceHolder("Note Title")

	contentEntry := widget.NewMultiLineEntry()
	contentEntry.SetPlaceHolder("Note Content")
	contentEntry.Wrapping = fyne.TextWrapWord

	saveBtn := widget.NewButton("Save", func() {
		if titleEntry.Text == "" {
			dialog.ShowInformation("Error", "Title cannot be empty", w)
			return
		}


		if state.currentNote == nil {
			saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				if writer == nil {
					return 
				}
				defer writer.Close()
				
				filePath := writer.URI().Path()
				
				encryptedContent, nonce, err := encryptNoteContent(state, contentEntry.Text)
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				
				_, err = writer.Write(encryptedContent)
				if err != nil {
					dialog.ShowError(fmt.Errorf("failed to write note file: %w", err), w)
					return
				}
				
				now := time.Now().Format(time.RFC3339)
				
				result, err := state.db.Exec(`
					INSERT INTO notes (user_id, title, encrypted_content, nonce, file_path, created_at, updated_at)
					VALUES (?, ?, ?, ?, ?, ?, ?)
				`, state.userID, titleEntry.Text, []byte("STORED_IN_FILE"), nonce, filePath, now, now)
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				
				// Get the ID of the newly inserted note
				noteID, err := result.LastInsertId()
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				
				// Add note to in-memory collection
				state.notes = append(state.notes, Note{
					ID:               noteID,
					Title:            titleEntry.Text,
					EncryptedContent: []byte("STORED_IN_FILE"),
					Nonce:            nonce,
					FilePath:         filePath,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				})
				
				notesList.Refresh()
				state.currentNote = nil
				titleEntry.SetText("")
				contentEntry.SetText("")
			}, w)
			
			saveDialog.SetFileName(titleEntry.Text + ".qsnote")
			saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".qsnote"}))
			saveDialog.Show()
		} else {
			// Update existing note
			err := updateNote(state, state.currentNote.ID, titleEntry.Text, contentEntry.Text)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			
			// Reload notes
			err = loadNotes(state)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			notesList.Refresh()
			state.currentNote = nil
			titleEntry.SetText("")
			contentEntry.SetText("")
		}
	})

	newBtn := widget.NewButton("New", func() {
		state.currentNote = nil
		titleEntry.SetText("")
		contentEntry.SetText("")
	})

	deleteBtn := widget.NewButton("Delete", func() {
		if state.currentNote == nil {
			dialog.ShowInformation("Error", "No note selected", w)
			return
		}

		dialog.ShowConfirm("Confirm", "Are you sure you want to delete this note?", func(confirm bool) {
			if confirm {
				err := deleteNote(state, state.currentNote.ID)
				if err != nil {
					dialog.ShowError(err, w)
					return
				}

				err = loadNotes(state)
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				notesList.Refresh()
				state.currentNote = nil
				titleEntry.SetText("")
				contentEntry.SetText("")
			}
		}, w)
	})

	importBtn := widget.NewButton("Import", func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if reader == nil {
				return 
			}
			defer reader.Close()
			
			fileName := filepath.Base(reader.URI().String())
			
			var noteID int64
			var title string
			
			err = state.db.QueryRow(`
				SELECT id, title FROM notes 
				WHERE file_path LIKE ? AND user_id = ?
			`, "%"+fileName, state.userID).Scan(&noteID, &title)
			
			if err != nil {
				dialog.ShowError(errors.New("This file is not a valid note or doesn't belong to you"), w)
				return
			}
			
			for i, note := range state.notes {
				if note.ID == noteID {
					notesList.Select(i)
					break
				}
			}
		}, w)
		
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".qsnote"}))
		fd.Show()
	})

	logoutBtn := widget.NewButton("Logout", func() {
		state.authenticated = false
		state.cryptoMgr = nil
		state.notes = nil
		state.currentNote = nil
		state.userID = 0
		loginScreen(w, state)
	})

	
	notesList.OnSelected = func(id widget.ListItemID) {
		state.currentNote = &state.notes[id]
		titleEntry.SetText(state.currentNote.Title)

		content, err := decryptNoteContent(state, state.currentNote)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		contentEntry.SetText(content)
	}


	split := container.NewHSplit(
		container.NewBorder(nil, nil, nil, nil, notesList),
		container.NewBorder(
			container.NewVBox(
				titleEntry,
				container.NewHBox(newBtn, saveBtn, deleteBtn, importBtn, logoutBtn),
			),
			nil, nil, nil,
			contentEntry,
		),
	)
	split.SetOffset(0.3)

	w.SetContent(split)
}

func loadNotes(state *AppState) error {
	if !state.authenticated {
		return errors.New("not authenticated")
	}

	rows, err := state.db.Query(`
		SELECT id, title, encrypted_content, nonce, file_path, created_at, updated_at
		FROM notes
		WHERE user_id = ?
		ORDER BY updated_at DESC
	`, state.userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	notes := []Note{}
	for rows.Next() {
		var note Note
		var createdAtStr, updatedAtStr string
		err := rows.Scan(&note.ID, &note.Title, &note.EncryptedContent, &note.Nonce, 
					&note.FilePath, &createdAtStr, &updatedAtStr)
		if err != nil {
			return err
		}

		note.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
		note.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAtStr)
		notes = append(notes, note)
	}

	state.notes = notes
	return nil
}

func createNote(state *AppState, title, content string) error {
	if !state.authenticated {
		return errors.New("not authenticated")
	}

	timestamp := time.Now().UnixNano()
	fileName := fmt.Sprintf("note_%d_%x.qsnote", timestamp, state.userID)
	filePath := filepath.Join(state.dataDir, fileName)

	encryptedContent, nonce, err := encryptNoteContent(state, content)
	if err != nil {
		return err
	}

	err = os.WriteFile(filePath, encryptedContent, 0600)
	if err != nil {
		return fmt.Errorf("failed to write note file: %w", err)
	}

	now := time.Now().Format(time.RFC3339)

	// Store a reference in the database
	result, err := state.db.Exec(`
		INSERT INTO notes (user_id, title, encrypted_content, nonce, file_path, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, state.userID, title, []byte("STORED_IN_FILE"), nonce, filePath, now, now)
	if err != nil {
		os.Remove(filePath)
		return err
	}

	noteID, err := result.LastInsertId()
	if err != nil {
		return err
	}

	state.notes = append(state.notes, Note{
		ID:               noteID,
		Title:            title,
		EncryptedContent: []byte("STORED_IN_FILE"),
		Nonce:            nonce,
		FilePath:         filePath,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	})

	return nil
}

func updateNote(state *AppState, noteID int64, title, content string) error {
	if !state.authenticated {
		return errors.New("not authenticated")
	}

	var filePath string
	
	for _, note := range state.notes {
		if note.ID == noteID {
			filePath = note.FilePath
			break
		}
	}

	if filePath == "" {
		return errors.New("note not found")
	}

	// Encrypt note content
	encryptedContent, nonce, err := encryptNoteContent(state, content)
	if err != nil {
		return err
	}

	// Create a new file handle with exclusive write access
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open note file: %w", err)
	}
	
	// Write encrypted content to file and close immediately
	_, err = file.Write(encryptedContent)
	file.Close() // Explicitly close the file to release the handle
	if err != nil {
		return fmt.Errorf("failed to write note file: %w", err)
	}

	now := time.Now().Format(time.RFC3339)

	// Update database reference
	_, err = state.db.Exec(`
		UPDATE notes
		SET title = ?, nonce = ?, updated_at = ?
		WHERE id = ? AND user_id = ?
	`, title, nonce, now, noteID, state.userID)

	return err
}

func deleteNote(state *AppState, noteID int64) error {
	if !state.authenticated {
		return errors.New("not authenticated")
	}

	// Get file path before deleting from database
	var filePath string
	err := state.db.QueryRow("SELECT file_path FROM notes WHERE id = ? AND user_id = ?", 
		noteID, state.userID).Scan(&filePath)
	if err != nil {
		return err
	}

	// Delete from database
	_, err = state.db.Exec("DELETE FROM notes WHERE id = ? AND user_id = ?", noteID, state.userID)
	if err != nil {
		return err
	}

	// Delete file
	if filePath != "" {
		err = os.Remove(filePath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete note file: %w", err)
		}
	}

	return nil
}

func register(state *AppState, username, password string) error {
	// Check if user already exists
	var count int
	err := state.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("username already exists")
	}

	// Generate secure salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	// Hash password using Argon2id
	passwordHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)

	// Generate Kyber key pair
	scheme := kyber768.Scheme()
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return err
	}

	// Serialize keys to bytes
	privateKeyBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return err
	}
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return err
	}

	// Generate AES key from password hash for key encryption
	keyEncryptionKey := deriveKeyEncryptionKey(passwordHash)

	// Encrypt private key with AES-GCM
	encryptedPrivateKey, err := aesGCMEncrypt(privateKeyBytes, keyEncryptionKey)
	if err != nil {
		return err
	}

	// Save user to database
	_, err = state.db.Exec(`
		INSERT INTO users (username, password_hash, salt, public_key, encrypted_private_key)
		VALUES (?, ?, ?, ?, ?)
	`, username, passwordHash, salt, publicKeyBytes, encryptedPrivateKey)

	return err
}

func login(state *AppState, username, password string) error {
	var userID int64
	var passwordHash, salt, publicKeyBytes, encryptedPrivateKey []byte

	err := state.db.QueryRow(`
		SELECT id, password_hash, salt, public_key, encrypted_private_key
		FROM users
		WHERE username = ?
	`, username).Scan(&userID, &passwordHash, &salt, &publicKeyBytes, &encryptedPrivateKey)

	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("invalid username or password")
		}
		return err
	}

	// Verify password
	inputPasswordHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	if !bytes.Equal(inputPasswordHash, passwordHash) {
		return errors.New("invalid username or password")
	}

	// Derive key encryption key from password hash
	keyEncryptionKey := deriveKeyEncryptionKey(inputPasswordHash)

	// Decrypt private key bytes
	privateKeyBytes, err := aesGCMDecrypt(encryptedPrivateKey, keyEncryptionKey)
	if err != nil {
		return errors.New("invalid password")
	}

	// Unmarshal private key
	scheme := kyber768.Scheme()
	privateKey, err := scheme.UnmarshalBinaryPrivateKey(privateKeyBytes)
	if err != nil {
		return err
	}

	// Unmarshal public key
	publicKey, err := scheme.UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		return err
	}

	// Derive consistent session key from password hash
	// This ensures the same key is generated on each login
	sessionKey := deriveSessionKey(inputPasswordHash, salt)

	// Set up crypto manager
	state.cryptoMgr = &CryptoManager{
		privateKey: privateKey,
		publicKey:  publicKey,
		sessionKey: sessionKey,
		passHash:   inputPasswordHash,
	}

	state.authenticated = true
	state.userID = userID
	return nil
}

// NEW FUNCTION: Derive a consistent session key from password hash and salt
func deriveSessionKey(passwordHash, salt []byte) []byte {
	// Use Argon2id to derive a consistent 32-byte (256-bit) key for AES-256
	// We use different parameters to make this key unique from the password hash
	return argon2.IDKey(passwordHash, salt, 2, 32*1024, 2, 32)
}

func encryptNoteContent(state *AppState, content string) ([]byte, []byte, error) {
	if !state.authenticated || state.cryptoMgr == nil {
		return nil, nil, errors.New("not authenticated")
	}

	plaintext := []byte(content)
	
	// Create a new AES cipher using the session key
	block, err := aes.NewCipher(state.cryptoMgr.sessionKey)
	if err != nil {
		return nil, nil, err
	}
	
	// Generate a random nonce
	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	
	// Create GCM instance with the AES cipher
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	
	// Encrypt and authenticate the plaintext
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	
	return ciphertext, nonce, nil
}

func decryptNoteContent(state *AppState, note *Note) (string, error) {
	if !state.authenticated || state.cryptoMgr == nil {
		return "", errors.New("not authenticated")
	}
	
	// If the note content is stored in a file
	var ciphertext []byte
	var err error
	
	if string(note.EncryptedContent) == "STORED_IN_FILE" {
		// Read encrypted content from file
		ciphertext, err = os.ReadFile(note.FilePath)
		if err != nil {
			return "", fmt.Errorf("failed to read note file: %w", err)
		}
	} else {
		ciphertext = note.EncryptedContent
	}
	
	// Create a new AES cipher using the session key
	block, err := aes.NewCipher(state.cryptoMgr.sessionKey)
	if err != nil {
		return "", err
	}
	
	// Create GCM instance with the AES cipher
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	
	// Decrypt the ciphertext
	plaintext, err := aesgcm.Open(nil, note.Nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}
	
	return string(plaintext), nil
}

// Helper functions for AES-GCM encryption
func aesGCMEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// Encrypt and prepend nonce
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func aesGCMDecrypt(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) < 12 {
		return nil, errors.New("ciphertext too short")
	}
	
	nonce := ciphertext[:12]
	ciphertext = ciphertext[12:]
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}

func deriveKeyEncryptionKey(passwordHash []byte) []byte {
	// Use first 32 bytes of password hash as AES-256 key
	return passwordHash[:32]
}

// Utility functions
func hexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}