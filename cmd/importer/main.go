package main

import (
	"os"

	sdk "github.com/PlakarKorp/go-kloset-sdk"
	"github.com/PlakarKorp/integrations/remarkable"
)

func main() {
	sdk.EntrypointImporter(os.Args, remarkable.NewImporter)
}
