package main

import (
	"os"

	sdk "github.com/PlakarKorp/go-kloset-sdk"
	"github.com/heph2/plakar-integration-remarkable"
)

func main() {
	sdk.EntrypointImporter(os.Args, remarkable.NewImporter)
}
