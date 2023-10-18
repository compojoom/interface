import { BigNumber } from '@ethersproject/bignumber'
import { arrayify, hexConcat, hexlify, splitSignature, stripZeros } from '@ethersproject/bytes'
import { Contract } from '@ethersproject/contracts'
import { keccak256 } from '@ethersproject/keccak256'
import { encode } from '@ethersproject/rlp'
import { t } from '@lingui/macro'
import { encrypt, init } from '@shutter-network/shutter-crypto'
import { SwapEventName } from '@uniswap/analytics-events'
import { Percent, V3_CORE_FACTORY_ADDRESSES } from '@uniswap/sdk-core'
import { SwapRouter, UNIVERSAL_ROUTER_ADDRESS } from '@uniswap/universal-router-sdk'
import IUniswapV3PoolEventsJSON from '@uniswap/v3-core/artifacts/contracts/interfaces/pool/IUniswapV3PoolEvents.sol/IUniswapV3PoolEvents.json'
import { computePoolAddress, FeeOptions, toHex } from '@uniswap/v3-sdk'
import { useWeb3React } from '@web3-react/core'
import { sendAnalyticsEvent, useTrace } from 'analytics'
import useBlockNumber from 'lib/hooks/useBlockNumber'
import { formatCommonPropertiesForTrade } from 'lib/utils/analytics'
import { useCallback } from 'react'
import { ClassicTrade, TradeFillType } from 'state/routing/types'
import { useUserSlippageTolerance } from 'state/user/hooks'
import { trace } from 'tracing/trace'
import { calculateGasMargin } from 'utils/calculateGasMargin'
import { UserRejectedRequestError, WrongChainError } from 'utils/errors'
import isZero from 'utils/isZero'
import { didUserReject } from 'utils/swapErrorToUserReadableMessage'

import { getEonKey, getNextEpoch, submitShutterTx } from '../utils/shutterCollator'
import { swapErrorToUserReadableMessage } from '../utils/swapErrorToUserReadableMessage'
import { PermitSignature } from './usePermitAllowance'

/** Thrown when gas estimation fails. This class of error usually requires an emulator to determine the root cause. */
class GasEstimationError extends Error {
  constructor() {
    super(t`Your swap is expected to fail.`)
  }
}

/**
 * Thrown when the user modifies the transaction in-wallet before submitting it.
 * In-wallet calldata modification nullifies any safeguards (eg slippage) from the interface, so we recommend reverting them immediately.
 */
class ModifiedSwapError extends Error {
  constructor() {
    super(
      t`Your swap was modified through your wallet. If this was a mistake, please cancel immediately or risk losing your funds.`
    )
  }
}

interface SwapOptions {
  slippageTolerance: Percent
  deadline?: BigNumber
  permit?: PermitSignature
  feeOptions?: FeeOptions
}

export function useUniversalRouterSwapCallback(
  trade: ClassicTrade | undefined,
  fiatValues: { amountIn?: number; amountOut?: number },
  options: SwapOptions
) {
  const { account, chainId, provider } = useWeb3React()
  const analyticsContext = useTrace()
  const blockNumber = useBlockNumber()
  const isAutoSlippage = useUserSlippageTolerance()[0] === 'auto'

  return useCallback(async () => {
    return trace('swap.send', async ({ setTraceData, setTraceStatus, setTraceError }) => {
      try {
        if (!account) throw new Error('missing account')
        if (!chainId) throw new Error('missing chainId')
        if (!provider) throw new Error('missing provider')
        if (!trade) throw new Error('missing trade')
        const connectedChainId = await provider.getSigner().getChainId()
        if (chainId !== connectedChainId) throw new WrongChainError()

        setTraceData('slippageTolerance', options.slippageTolerance.toFixed(2))

        // universal-router-sdk reconstructs V2Trade objects, so rather than updating the trade amounts to account for tax, we adjust the slippage tolerance as a workaround
        // TODO(WEB-2725): update universal-router-sdk to not reconstruct trades
        const taxAdjustedSlippageTolerance = options.slippageTolerance.add(trade.totalTaxRate)

        const { calldata: data, value } = SwapRouter.swapERC20CallParameters(trade, {
          slippageTolerance: taxAdjustedSlippageTolerance,
          deadlineOrPreviousBlockhash: options.deadline?.toString(),
          inputTokenPermit: options.permit,
          fee: options.feeOptions,
        })

        const tx = {
          from: account,
          to: UNIVERSAL_ROUTER_ADDRESS(chainId),
          data,
          // TODO(https://github.com/Uniswap/universal-router-sdk/issues/113): universal-router-sdk returns a non-hexlified value.
          ...(value && !isZero(value) ? { value: toHex(value) } : {}),
        }

        let gasEstimate: BigNumber
        try {
          gasEstimate = await provider.estimateGas(tx)
        } catch (gasError) {
          setTraceStatus('failed_precondition')
          setTraceError(gasError)
          sendAnalyticsEvent(SwapEventName.SWAP_ESTIMATE_GAS_CALL_FAILED, {
            ...formatCommonPropertiesForTrade(trade, options.slippageTolerance),
            ...analyticsContext,
            client_block_number: blockNumber,
            tx,
            error: gasError,
            isAutoSlippage,
          })
          console.warn(gasError)
          throw new GasEstimationError()
        }
        const gasLimit = calculateGasMargin(gasEstimate)
        setTraceData('gasLimit', gasLimit.toNumber())

        const dataForShutterTX = [tx.to, tx.data, tx.value]

        await init('http://localhost:3000/assets/shutter/shutter-crypto.wasm')

        const blockNum = await provider.getBlockNumber()
        const eonKey = await getEonKey(blockNum)
        const epoch = await getNextEpoch()
        // XXX potentially re-add stripZeros here
        const eonPublicKey = hexlify(Buffer.from(eonKey.eon_public_key, 'base64'))
        const epochId = Buffer.from(epoch.id, 'base64')
        const sigma = new Uint8Array(32)
        window.crypto.getRandomValues(sigma)

        const encryptedMessage = await encrypt(
          arrayify(encode(dataForShutterTX)),
          arrayify(eonPublicKey),
          arrayify(epochId),
          sigma
        )
        console.log('encrypted-message', encryptedMessage)

        const feeData = await provider.getFeeData()
        const nonce = await provider.getTransactionCount(account)
        const shutterTX = [
          hexlify(chainId), // ChainId
          hexlify(nonce), // Nonce
          feeData.maxPriorityFeePerGas?.toHexString(), // GasTipCap - maxPriorityFeePerGas
          feeData.maxFeePerGas?.toHexString(), // GAsFeeCap - map to maxFeePerGas
          gasLimit.toHexString(), // Gas - gasLimit
          hexlify(stripZeros(encryptedMessage)), // EncryptedPayload
          hexlify(stripZeros(epochId)),
          hexlify(blockNum),
        ]

        const txHash = keccak256(hexConcat(['0x50', encode(shutterTX)]))
        const address = await provider.getSigner().getAddress()
        const signedShutterTx = await provider.send('eth_sign', [address.toString(), txHash])

        const sig = splitSignature(signedShutterTx)

        shutterTX.push(hexlify(stripZeros(BigNumber.from(sig.recoveryParam).toHexString()))) // V
        shutterTX.push(hexlify(stripZeros(sig.r))) // r
        shutterTX.push(hexlify(stripZeros(sig.s))) // s

        const response = await new Promise((resolve, reject) => {
          return submitShutterTx({
            encrypted_tx: hexConcat(['0x50', encode(shutterTX)]),
            epoch: hexlify(stripZeros(epochId)),
          }).then((response) => {
            const pool = trade.routes[0].pools[0]
            // XXX we do we try to filter for this very specific event?
            // We only want to return the transaction hash of the above sent
            // transaction.
            // Can't we listen for contract calls with the original router contract
            // calldata, and from address?

            // FIXME fee doesn't exist on pool
            const currentPoolAddress = computePoolAddress({
              factoryAddress: V3_CORE_FACTORY_ADDRESSES[chainId],
              tokenA: pool.token0,
              tokenB: pool.token1,
              fee: pool.fee,
            })

            const routerContract = new Contract(currentPoolAddress, IUniswapV3PoolEventsJSON.abi, provider)

            routerContract.on(
              'Swap',
              async (sender, recipient, amount0In, amount1In, amount0Out, amount1Out, to, data) => {
                if (recipient === account) {
                  const decryptedTransaction = await data.getTransaction()
                  console.log(decryptedTransaction)
                  resolve(decryptedTransaction)
                }
              }
            )
          })
        })

        return {
          type: TradeFillType.Classic as const,
          response,
        }
      } catch (swapError: unknown) {
        if (swapError instanceof ModifiedSwapError) throw swapError

        // GasEstimationErrors are already traced when they are thrown.
        if (!(swapError instanceof GasEstimationError)) setTraceError(swapError)

        // Cancellations are not failures, and must be accounted for as 'cancelled'.
        if (didUserReject(swapError)) {
          setTraceStatus('cancelled')
          // This error type allows us to distinguish between user rejections and other errors later too.
          throw new UserRejectedRequestError(swapErrorToUserReadableMessage(swapError))
        }

        throw new Error(swapErrorToUserReadableMessage(swapError))
      }
    })
  }, [
    account,
    analyticsContext,
    blockNumber,
    chainId,
    fiatValues,
    options.deadline,
    options.feeOptions,
    options.permit,
    options.slippageTolerance,
    provider,
    trade,
    isAutoSlippage,
  ])
}
