package coreplainauth

import (
	"testing"
	"time"

	"github.com/scott-mescudi/gauth/database"
	tu "github.com/scott-mescudi/gauth/shared/testutils"
)

func TestRefreshHandler(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	pool, err := database.ConnectToDatabase("postgres", conn)
	if err != nil {
		t.Fatal(err)
	}

	ph, err := HashPassword("hey")
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.AddUser(t.Context(), "jack", "jack@jack.com", "user", ph, true)
	if err != nil {
		t.Fatal(err)
	}

	pa := &Coreplainauth{DB: pool, AccessTokenExpiration: 1 * time.Hour, RefreshTokenExpiration: 48 * time.Hour}

	_, rt, err := pa.LoginHandler(t.Context(), "jack", "hey", "")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = pa.RefreshHandler(t.Context(), rt)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = pa.RefreshHandler(t.Context(), "sds")
	if err == nil {
		t.Fatal("failed to throw error on inclaid token")
	}
}
