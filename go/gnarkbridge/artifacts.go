package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	gnarksolidity "github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/constraint"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

type artifactLayout struct {
	BuildDir             string `json:"buildDir"`
	LeafCount            int    `json:"leafCount"`
	ConstraintSystemPath string `json:"constraintSystemPath"`
	ProvingKeyPath       string `json:"provingKeyPath"`
	VerifyingKeyPath     string `json:"verifyingKeyPath"`
	VerifierSolidityPath string `json:"verifierSolidityPath"`
	MetadataPath         string `json:"metadataPath"`
}

type artifactMetadata struct {
	Backend          string   `json:"backend"`
	Curve            string   `json:"curve"`
	Kzg              string   `json:"kzg"`
	LeafCount        int      `json:"leafCount"`
	MerkleTreeDepth  int      `json:"merkleTreeDepth"`
	PoseidonVariant  string   `json:"poseidonVariant"`
	PublicInputOrder []string `json:"publicInputOrder"`
	ProofEncoding    string   `json:"proofEncoding"`
	VerifierContract string   `json:"verifierContract"`
	VerifierEntry    string   `json:"verifierEntry"`
}

func newArtifactLayout(buildDir string, leafCount int) artifactLayout {
	return artifactLayout{
		BuildDir:             buildDir,
		LeafCount:            leafCount,
		ConstraintSystemPath: filepath.Join(buildDir, "BraidOperation.scs"),
		ProvingKeyPath:       filepath.Join(buildDir, "BraidOperation.pk"),
		VerifyingKeyPath:     filepath.Join(buildDir, "BraidOperation.vk"),
		VerifierSolidityPath: filepath.Join(buildDir, "PlonkVerifier.sol"),
		MetadataPath:         filepath.Join(buildDir, "metadata.json"),
	}
}

func (layout artifactLayout) filesExist() bool {
	paths := []string{
		layout.ConstraintSystemPath,
		layout.ProvingKeyPath,
		layout.VerifyingKeyPath,
		layout.VerifierSolidityPath,
		layout.MetadataPath,
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}

	return true
}

func circuitForLeafCount(leafCount int) (frontend.Circuit, error) {
	switch leafCount {
	case 0:
		return &BraidOperationCircuitLeaf0{}, nil
	case 1:
		return &BraidOperationCircuitLeaf1{}, nil
	case 2:
		return &BraidOperationCircuitLeaf2{}, nil
	case 3:
		return &BraidOperationCircuitLeaf3{}, nil
	case 4:
		return &BraidOperationCircuitLeaf4{}, nil
	default:
		return nil, fmt.Errorf("unsupported leaf count %d", leafCount)
	}
}

func ensureArtifacts(buildDir string, leafCount int) (artifactLayout, error) {
	layout := newArtifactLayout(buildDir, leafCount)
	if layout.filesExist() {
		return layout, nil
	}

	if err := os.MkdirAll(layout.BuildDir, 0o755); err != nil {
		return layout, fmt.Errorf("create build dir: %w", err)
	}

	circuit, err := circuitForLeafCount(leafCount)
	if err != nil {
		return layout, err
	}

	compiled, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		scs.NewBuilder,
		circuit,
	)
	if err != nil {
		return layout, fmt.Errorf("compile circuit: %w", err)
	}

	sparse, ok := compiled.(*csbn254.SparseR1CS)
	if !ok {
		return layout, fmt.Errorf("unexpected constraint system type: %T", compiled)
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(sparse)
	if err != nil {
		return layout, fmt.Errorf("create unsafe kzg setup: %w", err)
	}

	provingKey, verifyingKey, err := plonk.Setup(compiled, srs, srsLagrange)
	if err != nil {
		return layout, fmt.Errorf("plonk setup: %w", err)
	}

	if err := writeConstraintSystem(layout.ConstraintSystemPath, compiled); err != nil {
		return layout, err
	}
	if err := writeWriterTo(layout.ProvingKeyPath, provingKey); err != nil {
		return layout, fmt.Errorf("write proving key: %w", err)
	}
	if err := writeWriterTo(layout.VerifyingKeyPath, verifyingKey); err != nil {
		return layout, fmt.Errorf("write verifying key: %w", err)
	}
	if err := exportSolidityVerifier(layout.VerifierSolidityPath, verifyingKey); err != nil {
		return layout, err
	}
	if err := writeMetadata(layout.MetadataPath, leafCount); err != nil {
		return layout, err
	}

	return layout, nil
}

func writeConstraintSystem(
	path string,
	system constraint.ConstraintSystem,
) error {
	return writeWriterTo(path, system)
}

func writeWriterTo(path string, value io.WriterTo) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer file.Close()

	if _, err := value.WriteTo(file); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}

func exportSolidityVerifier(
	path string,
	verifyingKey plonk.VerifyingKey,
) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create verifier solidity file: %w", err)
	}
	defer file.Close()

	err = verifyingKey.ExportSolidity(
		file,
		gnarksolidity.WithPragmaVersion("^0.8.24"),
	)
	if err != nil {
		return fmt.Errorf("export solidity verifier: %w", err)
	}

	return nil
}

func writeMetadata(path string, leafCount int) error {
	publicInputOrder := []string{
		"operation",
		"root",
		"outputCommitment",
		"nullifier",
	}
	for index := 0; index < leafCount; index++ {
		publicInputOrder = append(
			publicInputOrder,
			fmt.Sprintf("leafCommitment%d", index),
		)
	}

	metadata := artifactMetadata{
		Backend:          "plonk",
		Curve:            "bn254",
		Kzg:              "unsafe-local-dev",
		LeafCount:        leafCount,
		MerkleTreeDepth:  merkleTreeDepth,
		PoseidonVariant:  "circomlib-compatible-poseidon-bn254",
		PublicInputOrder: publicInputOrder,
		ProofEncoding:    "gnark-marshal-solidity-hex",
		VerifierContract: "PlonkVerifier",
		VerifierEntry:    "Verify(bytes,uint256[])",
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create metadata file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(metadata); err != nil {
		return fmt.Errorf("encode metadata: %w", err)
	}

	return nil
}

func readConstraintSystem(path string) (constraint.ConstraintSystem, error) {
	system := plonk.NewCS(ecc.BN254)

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open constraint system: %w", err)
	}
	defer file.Close()

	if _, err := system.ReadFrom(file); err != nil {
		return nil, fmt.Errorf("read constraint system: %w", err)
	}

	return system, nil
}

func readProvingKey(path string) (plonk.ProvingKey, error) {
	key := plonk.NewProvingKey(ecc.BN254)

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open proving key: %w", err)
	}
	defer file.Close()

	if _, err := key.ReadFrom(file); err != nil {
		return nil, fmt.Errorf("read proving key: %w", err)
	}

	return key, nil
}

func readVerifyingKey(path string) (plonk.VerifyingKey, error) {
	key := plonk.NewVerifyingKey(ecc.BN254)

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open verifying key: %w", err)
	}
	defer file.Close()

	if _, err := key.ReadFrom(file); err != nil {
		return nil, fmt.Errorf("read verifying key: %w", err)
	}

	return key, nil
}
