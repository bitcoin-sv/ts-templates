import Metanet from '../Metanet'
import { PrivateKey, Utils } from '@bsv/sdk'

describe('Metanet template', () => {
    it('creates metanet output', () => {
        const priv = PrivateKey.fromRandom()
        const script = new Metanet().lock(priv.toPublicKey(), null, ['subprotocol', 'data'])
        const tokens = script.toASM().split(' ')
        expect(tokens[0]).toEqual('OP_0')
        expect(tokens[1]).toEqual('OP_RETURN')
        expect(Utils.toUTF8(Utils.toArray(tokens[2], 'hex'))).toEqual('meta')
        expect(Utils.toUTF8(Utils.toArray(tokens[3], 'hex'))).toEqual(priv.toPublicKey().toString())
        expect(Utils.toUTF8(Utils.toArray(tokens[4], 'hex'))).toEqual('null')
        expect(Utils.toUTF8(Utils.toArray(tokens[5], 'hex'))).toEqual('subprotocol')
        expect(Utils.toUTF8(Utils.toArray(tokens[6], 'hex'))).toEqual('data')
    })

    it('fails to create metanet input', () => {
        expect(() => new Metanet().unlock()).toThrow()
    })
})
