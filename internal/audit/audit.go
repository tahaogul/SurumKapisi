package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Event represents an audit event to be logged
type Event struct {
	ProjectID    string
	OrgID        string
	Actor        string
	Action       string
	ResourceType string
	ResourceID   string
	Details      map[string]interface{}
}

// Logger handles writing audit events with optional hash-chaining
type Logger struct {
	db *sql.DB
}

// NewLogger creates a new audit logger
func NewLogger(db *sql.DB) *Logger {
	return &Logger{db: db}
}

// Log writes an audit event with hash-chaining
func (l *Logger) Log(event Event) error {
	eventID := uuid.New().String()
	detailsJSON, _ := json.Marshal(event.Details)

	// Get the previous hash for this project (hash-chaining)
	prevHash := l.getLastHash(event.ProjectID)

	// Compute current hash: SHA256(prev_hash + event_data)
	hashInput := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
		prevHash, eventID, event.Actor, event.Action,
		event.ResourceType, event.ResourceID,
		string(detailsJSON), time.Now().UTC().Format(time.RFC3339Nano))
	hash := sha256.Sum256([]byte(hashInput))
	currentHash := fmt.Sprintf("%x", hash)

	_, err := l.db.Exec(`
		INSERT INTO audit_events (event_id, project_id, org_id, actor, action, resource_type, resource_id, details, prev_hash, current_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		eventID,
		nullableString(event.ProjectID),
		nullableString(event.OrgID),
		event.Actor,
		event.Action,
		event.ResourceType,
		event.ResourceID,
		string(detailsJSON),
		prevHash,
		currentHash,
	)

	return err
}

// GetEvents retrieves audit events for a project
func (l *Logger) GetEvents(projectID string, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT event_id, project_id, org_id, actor, action, resource_type, resource_id,
		       details, prev_hash, current_hash, created_at
		FROM audit_events
		WHERE ($1 = '' OR project_id = $1::uuid)
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := l.db.Query(query, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []map[string]interface{}
	for rows.Next() {
		var (
			eventID, actor, action, resourceType, currentHash string
			projectIDVal, orgIDVal, resourceID, details, prevHash sql.NullString
			createdAt time.Time
		)

		if err := rows.Scan(&eventID, &projectIDVal, &orgIDVal, &actor, &action,
			&resourceType, &resourceID, &details, &prevHash, &currentHash, &createdAt); err != nil {
			return nil, err
		}

		event := map[string]interface{}{
			"event_id":      eventID,
			"project_id":    projectIDVal.String,
			"org_id":        orgIDVal.String,
			"actor":         actor,
			"action":        action,
			"resource_type": resourceType,
			"resource_id":   resourceID.String,
			"prev_hash":     prevHash.String,
			"current_hash":  currentHash,
			"created_at":    createdAt.Format(time.RFC3339),
		}

		if details.Valid {
			var d map[string]interface{}
			if json.Unmarshal([]byte(details.String), &d) == nil {
				event["details"] = d
			}
		}

		events = append(events, event)
	}

	return events, nil
}

// VerifyChain checks the hash chain integrity for a project
func (l *Logger) VerifyChain(projectID string) (bool, string, error) {
	rows, err := l.db.Query(`
		SELECT event_id, prev_hash, current_hash
		FROM audit_events
		WHERE project_id = $1
		ORDER BY id ASC`, projectID)
	if err != nil {
		return false, "", err
	}
	defer rows.Close()

	var lastHash string
	eventCount := 0

	for rows.Next() {
		var eventID, prevHash, currentHash string
		var prevHashNull sql.NullString

		if err := rows.Scan(&eventID, &prevHashNull, &currentHash); err != nil {
			return false, "", err
		}

		prevHash = prevHashNull.String

		if eventCount > 0 && prevHash != lastHash {
			return false, fmt.Sprintf("Chain break at event %s: expected prev_hash=%s, got %s",
				eventID, lastHash, prevHash), nil
		}

		lastHash = currentHash
		eventCount++
	}

	return true, fmt.Sprintf("Chain intact: %d events verified", eventCount), nil
}

func (l *Logger) getLastHash(projectID string) string {
	var hash sql.NullString
	err := l.db.QueryRow(`
		SELECT current_hash FROM audit_events
		WHERE project_id = $1
		ORDER BY id DESC LIMIT 1`, projectID).Scan(&hash)
	if err != nil || !hash.Valid {
		return "genesis"
	}
	return hash.String
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
