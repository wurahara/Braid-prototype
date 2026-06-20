package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	plonkbn254 "github.com/consensys/gnark/backend/plonk/bn254"
	gnarksolidity "github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
)

type operationLeafInput struct {
	Enabled      bool     `json:"enabled"`
	Subject      string   `json:"subject"`
	Secret       string   `json:"secret"`
	PathElements []string `json:"pathElements"`
	PathIndices  []int    `json:"pathIndices"`
}

type operationProofInput struct {
	Operation        string               `json:"operation"`
	Root             string               `json:"root"`
	OutputCommitment string               `json:"outputCommitment"`
	Nullifier        string               `json:"nullifier"`
	RelationDigest   string               `json:"relationDigest"`
	PredicateMin     string               `json:"predicateMin"`
	PredicateMax     string               `json:"predicateMax"`
	LeafCommitments  []string             `json:"leafCommitments"`
	OutputSubject    string               `json:"outputSubject"`
	OutputSecret     string               `json:"outputSecret"`
	Scope            string               `json:"scope"`
	PredicateValue   string               `json:"predicateValue"`
	RelationValues   []string             `json:"relationValues"`
	Leaves           []operationLeafInput `json:"leaves"`
}

type operationProofOutput struct {
	Proof        string   `json:"proof"`
	PublicInputs []string `json:"publicInputs"`
	Verified     bool     `json:"verified"`
	TimingMs     timingMs `json:"timingMs"`
}

type timingMs struct {
	LoadInput  float64 `json:"loadInput"`
	Witness    float64 `json:"witness"`
	ReadKeys   float64 `json:"readKeys"`
	Prove      float64 `json:"prove"`
	Verify     float64 `json:"verify"`
	Marshal    float64 `json:"marshal"`
	TotalInner float64 `json:"totalInner"`
}

type parsedOperationLeaf struct {
	Enabled      *big.Int
	Subject      *big.Int
	Secret       *big.Int
	PathElements [merkleTreeDepth]*big.Int
	PathIndices  [merkleTreeDepth]*big.Int
}

type parsedOperationInput struct {
	Operation        *big.Int
	Root             *big.Int
	OutputCommitment *big.Int
	Nullifier        *big.Int
	RelationDigest   *big.Int
	PredicateMin     *big.Int
	PredicateMax     *big.Int
	LeafCommitments  [maxLeaves]*big.Int
	OutputSubject    *big.Int
	OutputSecret     *big.Int
	Scope            *big.Int
	PredicateValue   *big.Int
	RelationValues   [relationValues]*big.Int
	Leaves           [maxLeaves]parsedOperationLeaf
}

func proveOperation(
	buildDir string,
	inputPath string,
) (*operationProofOutput, error) {
	startedAt := time.Now()
	loadStartedAt := time.Now()
	input, err := loadOperationProofInput(inputPath)
	if err != nil {
		return nil, err
	}

	parsed, err := parseOperationProofInput(input)
	if err != nil {
		return nil, err
	}
	loadDuration := time.Since(loadStartedAt)

	leafCount := countEnabledLeaves(parsed)
	layout, err := ensureArtifacts(buildDir, leafCount)
	if err != nil {
		return nil, err
	}

	witnessStartedAt := time.Now()
	assignment, err := buildWitnessAssignment(parsed, leafCount)
	if err != nil {
		return nil, err
	}
	fullWitness, err := frontend.NewWitness(
		assignment,
		ecc.BN254.ScalarField(),
	)
	if err != nil {
		return nil, fmt.Errorf("build full witness: %w", err)
	}

	publicWitness, err := frontend.NewWitness(
		assignment,
		ecc.BN254.ScalarField(),
		frontend.PublicOnly(),
	)
	if err != nil {
		return nil, fmt.Errorf("build public witness: %w", err)
	}
	witnessDuration := time.Since(witnessStartedAt)

	readStartedAt := time.Now()
	system, err := readConstraintSystem(layout.ConstraintSystemPath)
	if err != nil {
		return nil, err
	}
	provingKey, err := readProvingKey(layout.ProvingKeyPath)
	if err != nil {
		return nil, err
	}
	verifyingKey, err := readVerifyingKey(layout.VerifyingKeyPath)
	if err != nil {
		return nil, err
	}
	readDuration := time.Since(readStartedAt)

	proveStartedAt := time.Now()
	proof, err := plonk.Prove(
		system,
		provingKey,
		fullWitness,
		gnarksolidity.WithProverTargetSolidityVerifier(backend.PLONK),
	)
	if err != nil {
		return nil, fmt.Errorf("plonk prove: %w", err)
	}
	proveDuration := time.Since(proveStartedAt)

	verifyStartedAt := time.Now()
	if err := plonk.Verify(
		proof,
		verifyingKey,
		publicWitness,
		gnarksolidity.WithVerifierTargetSolidityVerifier(backend.PLONK),
	); err != nil {
		return nil, fmt.Errorf("plonk verify: %w", err)
	}
	verifyDuration := time.Since(verifyStartedAt)

	marshalStartedAt := time.Now()
	solidityProof, ok := proof.(*plonkbn254.Proof)
	if !ok {
		return nil, fmt.Errorf("unexpected proof type: %T", proof)
	}
	marshaledProof := solidityProof.MarshalSolidity()
	marshalDuration := time.Since(marshalStartedAt)

	return &operationProofOutput{
		Proof:        "0x" + hex.EncodeToString(marshaledProof),
		PublicInputs: publicInputsFor(parsed, leafCount),
		Verified:     true,
		TimingMs: timingMs{
			LoadInput:  durationMs(loadDuration),
			Witness:    durationMs(witnessDuration),
			ReadKeys:   durationMs(readDuration),
			Prove:      durationMs(proveDuration),
			Verify:     durationMs(verifyDuration),
			Marshal:    durationMs(marshalDuration),
			TotalInner: durationMs(time.Since(startedAt)),
		},
	}, nil
}

func publicInputsFor(input *parsedOperationInput, leafCount int) []string {
	publicInputs := []string{
		input.Operation.String(),
		input.Root.String(),
		input.OutputCommitment.String(),
		input.Nullifier.String(),
	}

	for index := 0; index < leafCount; index++ {
		publicInputs = append(publicInputs, input.LeafCommitments[index].String())
	}

	return publicInputs
}

func durationMs(duration time.Duration) float64 {
	return float64(duration.Microseconds()) / 1000
}

func loadOperationProofInput(path string) (*operationProofInput, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open proof input: %w", err)
	}
	defer file.Close()

	var input operationProofInput
	if err := json.NewDecoder(file).Decode(&input); err != nil {
		return nil, fmt.Errorf("decode proof input: %w", err)
	}

	return &input, nil
}

func parseOperationProofInput(
	input *operationProofInput,
) (*parsedOperationInput, error) {
	if len(input.RelationValues) != relationValues {
		return nil, fmt.Errorf(
			"expected %d relation values, received %d",
			relationValues,
			len(input.RelationValues),
		)
	}
	if len(input.Leaves) != maxLeaves {
		return nil, fmt.Errorf(
			"expected %d leaves, received %d",
			maxLeaves,
			len(input.Leaves),
		)
	}
	if len(input.LeafCommitments) != maxLeaves {
		return nil, fmt.Errorf(
			"expected %d leaf commitments, received %d",
			maxLeaves,
			len(input.LeafCommitments),
		)
	}

	parsed := &parsedOperationInput{}
	scalars := []struct {
		name   string
		raw    string
		target **big.Int
	}{
		{"operation", input.Operation, &parsed.Operation},
		{"root", input.Root, &parsed.Root},
		{"output commitment", input.OutputCommitment, &parsed.OutputCommitment},
		{"nullifier", input.Nullifier, &parsed.Nullifier},
		{"relation digest", input.RelationDigest, &parsed.RelationDigest},
		{"predicate min", input.PredicateMin, &parsed.PredicateMin},
		{"predicate max", input.PredicateMax, &parsed.PredicateMax},
		{"output subject", input.OutputSubject, &parsed.OutputSubject},
		{"output secret", input.OutputSecret, &parsed.OutputSecret},
		{"scope", input.Scope, &parsed.Scope},
		{"predicate value", input.PredicateValue, &parsed.PredicateValue},
	}

	for _, scalar := range scalars {
		value, err := parseBigInt(scalar.raw)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", scalar.name, err)
		}
		*scalar.target = value
	}

	for index, value := range input.RelationValues {
		parsedValue, err := parseBigInt(value)
		if err != nil {
			return nil, fmt.Errorf("parse relation value %d: %w", index, err)
		}
		parsed.RelationValues[index] = parsedValue
	}

	for index, value := range input.LeafCommitments {
		parsedValue, err := parseBigInt(value)
		if err != nil {
			return nil, fmt.Errorf("parse leaf commitment %d: %w", index, err)
		}
		parsed.LeafCommitments[index] = parsedValue
	}

	for index, leaf := range input.Leaves {
		parsedLeaf, err := parseOperationLeaf(index, leaf)
		if err != nil {
			return nil, err
		}
		parsed.Leaves[index] = parsedLeaf
	}

	return parsed, nil
}

func parseOperationLeaf(
	index int,
	leaf operationLeafInput,
) (parsedOperationLeaf, error) {
	if len(leaf.PathElements) != merkleTreeDepth {
		return parsedOperationLeaf{}, fmt.Errorf(
			"expected %d path elements for leaf %d, received %d",
			merkleTreeDepth,
			index,
			len(leaf.PathElements),
		)
	}
	if len(leaf.PathIndices) != merkleTreeDepth {
		return parsedOperationLeaf{}, fmt.Errorf(
			"expected %d path indices for leaf %d, received %d",
			merkleTreeDepth,
			index,
			len(leaf.PathIndices),
		)
	}

	enabled := big.NewInt(0)
	if leaf.Enabled {
		enabled = big.NewInt(1)
	}

	subject, err := parseBigInt(leaf.Subject)
	if err != nil {
		return parsedOperationLeaf{}, fmt.Errorf("parse leaf %d subject: %w", index, err)
	}
	secret, err := parseBigInt(leaf.Secret)
	if err != nil {
		return parsedOperationLeaf{}, fmt.Errorf("parse leaf %d secret: %w", index, err)
	}

	parsed := parsedOperationLeaf{
		Enabled: enabled,
		Subject: subject,
		Secret:  secret,
	}

	for pathIndex, value := range leaf.PathElements {
		element, err := parseBigInt(value)
		if err != nil {
			return parsedOperationLeaf{}, fmt.Errorf(
				"parse leaf %d path element %d: %w",
				index,
				pathIndex,
				err,
			)
		}
		parsed.PathElements[pathIndex] = element
	}

	for pathIndex, value := range leaf.PathIndices {
		if value != 0 && value != 1 {
			return parsedOperationLeaf{}, fmt.Errorf(
				"leaf %d path index %d must be 0 or 1",
				index,
				pathIndex,
			)
		}
		parsed.PathIndices[pathIndex] = big.NewInt(int64(value))
	}

	return parsed, nil
}

func parseBigInt(value string) (*big.Int, error) {
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal integer %q", value)
	}

	return parsed, nil
}

func countEnabledLeaves(input *parsedOperationInput) int {
	count := 0
	for _, leaf := range input.Leaves {
		if leaf.Enabled == nil || leaf.Enabled.Sign() == 0 {
			break
		}
		count++
	}

	return count
}

func buildWitnessAssignment(
	input *parsedOperationInput,
	leafCount int,
) (frontend.Circuit, error) {
	base := BraidOperationCircuit{
		Operation:        input.Operation,
		Root:             input.Root,
		OutputCommitment: input.OutputCommitment,
		Nullifier:        input.Nullifier,
		RelationDigest:   input.RelationDigest,
		PredicateMin:     input.PredicateMin,
		PredicateMax:     input.PredicateMax,
		OutputSubject:    input.OutputSubject,
		OutputSecret:     input.OutputSecret,
		Scope:            input.Scope,
		PredicateValue:   input.PredicateValue,
	}

	for index := 0; index < relationValues; index++ {
		base.RelationValues[index] = input.RelationValues[index]
	}

	for leafIndex := 0; leafIndex < maxLeaves; leafIndex++ {
		base.LeafSubjects[leafIndex] = input.Leaves[leafIndex].Subject
		base.LeafSecrets[leafIndex] = input.Leaves[leafIndex].Secret
		base.LeafEnabled[leafIndex] = input.Leaves[leafIndex].Enabled

		for pathIndex := 0; pathIndex < merkleTreeDepth; pathIndex++ {
			base.PathElements[leafIndex][pathIndex] =
				input.Leaves[leafIndex].PathElements[pathIndex]
			base.PathIndices[leafIndex][pathIndex] =
				input.Leaves[leafIndex].PathIndices[pathIndex]
		}
	}

	switch leafCount {
	case 0:
		return &BraidOperationCircuitLeaf0{BraidOperationCircuit: base}, nil
	case 1:
		return &BraidOperationCircuitLeaf1{
			BraidOperationCircuit: base,
			LeafCommitment0:       input.LeafCommitments[0],
		}, nil
	case 2:
		return &BraidOperationCircuitLeaf2{
			BraidOperationCircuit: base,
			LeafCommitment0:       input.LeafCommitments[0],
			LeafCommitment1:       input.LeafCommitments[1],
		}, nil
	case 3:
		return &BraidOperationCircuitLeaf3{
			BraidOperationCircuit: base,
			LeafCommitment0:       input.LeafCommitments[0],
			LeafCommitment1:       input.LeafCommitments[1],
			LeafCommitment2:       input.LeafCommitments[2],
		}, nil
	case 4:
		return &BraidOperationCircuitLeaf4{
			BraidOperationCircuit: base,
			LeafCommitment0:       input.LeafCommitments[0],
			LeafCommitment1:       input.LeafCommitments[1],
			LeafCommitment2:       input.LeafCommitments[2],
			LeafCommitment3:       input.LeafCommitments[3],
		}, nil
	default:
		return nil, fmt.Errorf("unsupported leaf count %d", leafCount)
	}
}
