import MultiPushDrop from '../MultiPushDrop'
import { OP, WalletInterface, WalletCounterparty, PubKeyHex, SecurityLevel, Transaction, CompletedProtoWallet, PrivateKey, PublicKey, Utils, Script, Spend, LockingScript, UnlockingScript } from '@bsv/sdk'

// Helper function like createDecodeRedeem from PushDrop tests
const testLockUnlockDecode = async (
  creatorMultiPushDrop: MultiPushDrop,
  creatorWallet: WalletInterface,
  fields: number[][],
  protocolID: [SecurityLevel, string],
  keyID: string,
  ownerPrivateKeys: PrivateKey[],
  signOutputs: 'all' | 'none' | 'single' = 'all',
  anyoneCanPay: boolean = false
): Promise<void> => {
  // --- Lock ---
  const counterparties = ownerPrivateKeys.map(x => x.toPublicKey().toString())
  const lockingScript = await creatorMultiPushDrop.lock(
    fields,
    protocolID,
    keyID,
    counterparties
  )
  expect(lockingScript).toBeInstanceOf(LockingScript)

  // --- Decode ---
  const decoded = MultiPushDrop.decode(lockingScript)
  expect(decoded.fields).toEqual(fields)
  expect(decoded.lockingPublicKeys.length).toEqual(ownerPrivateKeys.length)

  // Verify decoded keys match derived keys
  const derivedKeys: PubKeyHex[] = []
  for (const c of counterparties) {
    const { publicKey } = await creatorWallet.getPublicKey({
      protocolID, keyID, counterparty: c
    })
    derivedKeys.push(publicKey)
  }
  expect(decoded.lockingPublicKeys).toEqual(derivedKeys)

  // --- Unlock (for each counterparty) ---
  const satoshis = 1000 // Use a non-dust amount

  const sourceTx = new Transaction(
    1, [], [{ lockingScript, satoshis }], 0
  )
  const sourceOutputIndex = 0
  const { publicKey: creatorIdentityKey } = await creatorWallet.getPublicKey({ identityKey: true })

  for (let i = 0; i < ownerPrivateKeys.length; i++) {
    const ownerWallet = new CompletedProtoWallet(ownerPrivateKeys[i])
    const ownerMultiPushDrop = new MultiPushDrop(ownerWallet)
    console.log(`Testing unlock with counterparty index ${i}`)

    const unlockingTemplate = ownerMultiPushDrop.unlock(
      protocolID,
      keyID,
      creatorIdentityKey,
      signOutputs,
      anyoneCanPay
    )

    // Create a dummy spending transaction
    const spendTx = new Transaction(
      1,
      [{
        sourceTransaction: sourceTx, // Link for signing context
        sourceOutputIndex,
        // unlockingScript will be added by sign method
        sequence: 0xffffffff
      }],
      [{ // Dummy output
        lockingScript: Script.fromASM('OP_RETURN'),
        satoshis: satoshis - 500 // Account for potential fees
      }],
      0
    )

    // Sign to get the unlocking script
    if (ownerPrivateKeys.length > 1) {
      debugger
    }
    const unlockingScript = await unlockingTemplate.sign(spendTx, 0)
    expect(unlockingScript).toBeInstanceOf(UnlockingScript)
    expect(unlockingScript.chunks.length).toBe(2) // Signature + Index
    // Verify index chunk
    const indexChunk = unlockingScript.chunks[1]
    let decodedIndex: number
    if (indexChunk.op === OP.OP_0) decodedIndex = 0
    else if (indexChunk.op >= OP.OP_1 && indexChunk.op <= OP.OP_16) decodedIndex = indexChunk.op - OP.OP_1 + 1
    else if (indexChunk.data?.length === 1) decodedIndex = indexChunk.data[0]
    else throw new Error('Cannot decode index')
    expect(decodedIndex).toEqual(i) // Ensure the index matches the loop counter

    const estimatedLength = await unlockingTemplate.estimateLength(null as unknown as Transaction, 0)
    // Check if length is reasonable (e.g., 74 +/- a few bytes)
    expect(estimatedLength).toBeGreaterThanOrEqual(72)
    expect(estimatedLength).toBeLessThanOrEqual(80)

    // --- Verify Spend ---
    const spend = new Spend({
      sourceTXID: sourceTx.id('hex'),
      sourceOutputIndex,
      sourceSatoshis: satoshis,
      lockingScript, // From lock step
      transactionVersion: spendTx.version,
      otherInputs: [], // No other inputs in this simple case
      inputIndex: 0,
      unlockingScript, // From sign step
      outputs: spendTx.outputs,
      inputSequence: spendTx.inputs[0].sequence ?? 0xffffffff,
      lockTime: spendTx.lockTime
    })
    const valid = spend.validate()
    expect(valid).toBe(true)
  }
}

describe('MultiPushDrop', () => {
  let selfKey: PrivateKey
  let wallet: WalletInterface
  let multiPushDrop: MultiPushDrop
  let counterparty1Key: PrivateKey
  let counterparty1PubKeyHex: PubKeyHex
  let counterparty2Key: PrivateKey
  let counterparty2PubKeyHex: PubKeyHex
  const protocolID: [SecurityLevel, string] = [0, 'tests']
  const keyID = 'test-key-123'

  beforeEach(() => {
    selfKey = PrivateKey.fromRandom()
    counterparty1Key = PrivateKey.fromRandom()
    counterparty1PubKeyHex = counterparty1Key.toPublicKey().toString()
    counterparty2Key = PrivateKey.fromRandom()
    counterparty2PubKeyHex = counterparty2Key.toPublicKey().toString()

    // Use CompletedProtoWallet or mock as needed
    wallet = new CompletedProtoWallet(selfKey)
    multiPushDrop = new MultiPushDrop(wallet)
  })

  it('should lock, decode, and unlock with a single key (self)', async () => {
    await testLockUnlockDecode(
      multiPushDrop,
      wallet,
      [[1, 2, 3]],
      protocolID,
      keyID,
      [selfKey]
    )
  })

  it('should lock, decode, and unlock with a single key (external)', async () => {
    await testLockUnlockDecode(
      multiPushDrop,
      wallet,
      [[0xaa, 0xbb]],
      protocolID,
      keyID,
      [counterparty1Key]
    )
  })

  it('should lock, decode, and unlock with two keys (self, external)', async () => {
    await testLockUnlockDecode(
      multiPushDrop,
      wallet,
      [Utils.toArray('hello', 'utf8')],
      protocolID,
      keyID,
      [counterparty1Key, selfKey]
    )
  })

  it('should lock, decode, and unlock with three keys (self, external1, external2)', async () => {
    await testLockUnlockDecode(
      multiPushDrop,
      wallet,
      [[1], [1], [0xff]],
      protocolID,
      keyID,
      [selfKey, counterparty1Key, counterparty2Key]
    )
  })

  it('should handle empty fields', async () => {
    await testLockUnlockDecode(
      multiPushDrop,
      wallet,
      [],
      protocolID,
      keyID,
      [selfKey, counterparty1Key]
    )
  })

  it('should handle large fields', async () => {
    await testLockUnlockDecode(
      multiPushDrop,
      wallet,
      [new Array(100).fill(0xaa), new Array(80).fill(0xbb)],
      protocolID,
      keyID,
      [selfKey, counterparty1Key]
    )
  })

  it('should handle different signOutputs modes (anyonecanpay=false)', async () => {
    const counterparties = [selfKey, counterparty1Key]
    const fields = [[1]]
    await testLockUnlockDecode(multiPushDrop, wallet, fields, protocolID, keyID, counterparties, 'all', false)
    await testLockUnlockDecode(multiPushDrop, wallet, fields, protocolID, keyID, counterparties, 'none', false)
    await testLockUnlockDecode(multiPushDrop, wallet, fields, protocolID, keyID, counterparties, 'single', false)
  })

  it('should handle different signOutputs modes (anyonecanpay=true)', async () => {
    const counterparties = [selfKey, counterparty1Key]
    const fields = [[2]]
    await testLockUnlockDecode(multiPushDrop, wallet, fields, protocolID, keyID, counterparties, 'all', true)
    await testLockUnlockDecode(multiPushDrop, wallet, fields, protocolID, keyID, counterparties, 'none', true)
    await testLockUnlockDecode(multiPushDrop, wallet, fields, protocolID, keyID, counterparties, 'single', true)
  })

  it('decode should fail on invalid script structure', async () => {
    const invalidScript1 = Script.fromASM('OP_1 deadbeef OP_CHECKSIGVERIFY') // Missing keys/logic
    const invalidScript2 = Script.fromASM('OP_2 deadbeef20 deadbeef21 OP_PICK OP_CHECKSIGVERIFY') // Missing OP_1ADD
    const invalidScript3 = await multiPushDrop.lock([[1]], protocolID, keyID, ['self'])
    invalidScript3.chunks.splice(2, 1) // Remove OP_1ADD

    expect(() => MultiPushDrop.decode(invalidScript1)).toThrow()
    expect(() => MultiPushDrop.decode(invalidScript2)).toThrow()
    expect(() => MultiPushDrop.decode(invalidScript3)).toThrow(/Expected OP_1ADD/)
  })

  it('lock should fail with empty counterparties array', async () => {
    await expect(multiPushDrop.lock(
      [[1]],
      protocolID,
      keyID,
      []
    )).rejects.toThrow('MultiPushDrop requires at least one counterparty.')
  })

  // it('unlock should fail if unlocker key is not in the list', async () => {
  //   const lockingScript = await multiPushDrop.lock([[1]], protocolID, keyID, ['self'])
  //   const sourceTx = new Transaction(1, [], [{ lockingScript, satoshis: 1000 }], 0)
  //   const spendTx = new Transaction(1, [{ sourceTransaction: sourceTx, sourceOutputIndex: 0 }], [], 0)

  //   const unknownKey = PrivateKey.fromRandom()
  //   const unknownPubKeyHex = unknownKey.toPublicKey().toString()
  //   const walletWithUnknown = new CompletedProtoWallet(PrivateKey.fromRandom())
  //   const mpdWithUnknown = new MultiPushDrop(walletWithUnknown)

  //   const unlockingTemplate = mpdWithUnknown.unlock(
  //     protocolID,
  //     keyID,
  //     unknownPubKeyHex, // Try to unlock with a key not in the lock list
  //     ['self'] // The original list
  //   )

  //   await expect(unlockingTemplate.sign(spendTx, 0)).rejects.toThrow(/Unlocker key derived .* not found/)
  // })
})
