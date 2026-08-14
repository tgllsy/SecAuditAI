package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractRouteInfo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "UserController.java")
	source := `package demo;

@RestController
@RequestMapping("/api")
public class UserController {
    @GetMapping("/users")
    public String list() {
        return "ok";
    }
}`

	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}

	if got := ExtractRouteInfo(path, 8); got != "GET /api/users" {
		t.Fatalf("ExtractRouteInfo() = %q, want %q", got, "GET /api/users")
	}
}
