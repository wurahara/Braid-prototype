import ganache from "ganache";
import {
  createPublicClient,
  createWalletClient,
  custom,
  defineChain,
  getContract,
  type Abi,
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  createPoseidon2Artifact,
  type CompiledContractArtifact,
} from "./solidity.ts";

export interface LocalBraidContracts {
  poseidon: {
    address: Address;
    abi: Abi;
  };
  verifiers: Array<{
    address: Address;
    abi: Abi;
  }>;
  registry: {
    address: Address;
    abi: Abi;
  };
}

export interface LocalBraidChain {
  publicClient: PublicClient;
  walletClient: WalletClient;
  account: ReturnType<typeof privateKeyToAccount>;
  contracts: LocalBraidContracts;
  close: () => Promise<void>;
}

function localChainDefinition() {
  return defineChain({
    id: 1337,
    name: "braid-ganache",
    nativeCurrency: {
      decimals: 18,
      name: "Ether",
      symbol: "ETH",
    },
    rpcUrls: {
      default: {
        http: ["http://127.0.0.1:8545"],
      },
    },
  });
}

async function deploy(
  walletClient: WalletClient,
  publicClient: PublicClient,
  account: ReturnType<typeof privateKeyToAccount>,
  artifact: CompiledContractArtifact,
  args: readonly unknown[] = [],
): Promise<Address> {
  const hash = await walletClient.deployContract({
    abi: artifact.abi,
    account,
    args,
    bytecode: artifact.bytecode,
    chain: walletClient.chain,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (!receipt.contractAddress) {
    throw new Error("Contract deployment did not return an address");
  }
  return receipt.contractAddress;
}

export async function deployLocalBraidChain(
  artifacts: Record<string, CompiledContractArtifact>,
): Promise<LocalBraidChain> {
  const provider = ganache.provider({
    logging: {
      quiet: true,
    },
    wallet: {
      totalAccounts: 3,
    },
  });
  const firstAccount = Object.values(provider.getInitialAccounts())[0] as {
    secretKey: Hex;
  };
  const account = privateKeyToAccount(firstAccount.secretKey);
  const chain = localChainDefinition();
  const transport = custom(provider);
  const publicClient = createPublicClient({
    chain,
    transport,
  });
  const walletClient = createWalletClient({
    account,
    chain,
    transport,
  });

  const poseidonArtifact = createPoseidon2Artifact();
  const registryArtifact =
    artifacts["contracts/BraidRegistry.sol:BraidRegistry"];
  const verifierArtifacts = Object.entries(artifacts)
    .filter(([artifactKey]) =>
      artifactKey.startsWith("contracts/generated/PlonkVerifierLeaf"),
    )
    .sort(([leftKey], [rightKey]) => {
      const leftIndex = Number(leftKey.match(/Leaf(\d+)\.sol:/)?.[1] ?? "-1");
      const rightIndex = Number(rightKey.match(/Leaf(\d+)\.sol:/)?.[1] ?? "-1");
      return leftIndex - rightIndex;
    })
    .map(([, artifact]) => artifact);

  const poseidonAddress = await deploy(
    walletClient,
    publicClient,
    account,
    poseidonArtifact,
  );
  const verifierContracts: Array<{ address: Address; abi: Abi }> = [];
  for (const verifierArtifact of verifierArtifacts) {
    const verifierAddress = await deploy(
      walletClient,
      publicClient,
      account,
      verifierArtifact,
    );
    verifierContracts.push({
      address: verifierAddress,
      abi: verifierArtifact.abi,
    });
  }
  const registryAddress = await deploy(
    walletClient,
    publicClient,
    account,
    registryArtifact,
    [
      32,
      poseidonAddress,
      verifierContracts.map((verifier) => verifier.address),
    ],
  );

  return {
    publicClient,
    walletClient,
    account,
    contracts: {
      poseidon: {
        address: poseidonAddress,
        abi: poseidonArtifact.abi,
      },
      verifiers: verifierContracts,
      registry: {
        address: registryAddress,
        abi: registryArtifact.abi,
      },
    },
    close: async () => {
      provider.disconnect();
    },
  };
}

export async function writeContractAndWait(
  chain: LocalBraidChain,
  contract: { abi: Abi; address: Address },
  functionName: string,
  args: readonly unknown[],
): Promise<void> {
  const hash = await chain.walletClient.writeContract({
    abi: contract.abi,
    account: chain.account,
    address: contract.address,
    args,
    chain: chain.walletClient.chain,
    functionName,
  });

  await chain.publicClient.waitForTransactionReceipt({ hash });
}

export async function readContract<T>(
  chain: LocalBraidChain,
  contract: { abi: Abi; address: Address },
  functionName: string,
  args: readonly unknown[] = [],
): Promise<T> {
  return (await chain.publicClient.readContract({
    abi: contract.abi,
    address: contract.address,
    args,
    functionName,
  })) as T;
}

export function getTypedContract(
  chain: LocalBraidChain,
  contract: { abi: Abi; address: Address },
) {
  return getContract({
    abi: contract.abi,
    address: contract.address,
    client: {
      public: chain.publicClient,
      wallet: chain.walletClient,
    },
  });
}
