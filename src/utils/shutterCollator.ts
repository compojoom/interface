const COLLATOR_URL = 'http://localhost:3001/v1'

type shutterTx = {
  encrypted_tx: string
  epoch: string
}
// function to getNextEpoch
export const getNextEpoch = async () => {
  const response = await fetch(`${COLLATOR_URL}/next-epoch`)
  return response.json()
}

export const getEonKey = async (activationBlock: number) => {
  const response = await fetch(`${COLLATOR_URL}/eon?activation_block=${activationBlock}`)
  return response.json()
}

export const submitShutterTx = async (tx: shutterTx) => {
  console.log('submitShutterTx', tx)
  const response = await fetch(`${COLLATOR_URL}/tx`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(tx),
  })
  return response.json()
}
