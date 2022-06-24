import { ethers, BigNumber } from 'ethers'
import type { Result } from 'ethers/lib/utils'

export interface Env {
	SIGNER_KEY: string
	BUCKET: R2Bucket
}

const rpcUrl = 'https://rei-rpc.moonrhythm.io'
const contractAddress = '0x11B6a7Fd205AB1a701Ee1d5564cDfA8dD152d47f'
const hour = 3600
const chainIdHex = '0xd903'
const thumbnailMaxSize = 1 << 20

function now() {
	return Math.floor(Date.now() / 1000)
}

interface RpcResponse {
	result: string
}

interface FileResult extends Result {
	sender: string
	maxSize: BigNumber
	uploadFee: BigNumber
	downloadFee: BigNumber
	active: boolean
	paidCount: BigNumber
}

interface PaidResult extends Result {
	b: boolean
}

interface PriceRequest {
	sender: string
	maxSize: number
}

async function ethCall(callData: string): Promise<string> {
	const resp = await fetch(rpcUrl, {
		method: 'POST',
		headers: {
			'content-type': 'application/json'
		},
		body: JSON.stringify({
			id: '1',
			method: 'eth_call',
			params: [
				{ to: contractAddress, data: callData },
				'latest'
			]
		})
	})
	return (await resp.json<RpcResponse>()).result
}

// price returns price for given file metadata
async function price(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
	const req: PriceRequest = await request.json()
	if (!ethers.utils.isAddress(req.sender)) {
		return new Response('invalid request', { status: 400 })
	}

	const sender = ethers.utils.getAddress(req.sender)
	const maxSize = BigNumber.from(req.maxSize)
	const fee = ethers.utils.parseEther('1')
	const deadline = BigNumber.from(now() + (1 * hour))

	const hash = ethers.utils.solidityKeccak256(
		['address', 'uint256', 'uint256', 'uint256'],
		[sender, maxSize, fee, deadline])

	const signer = new ethers.Wallet(env.SIGNER_KEY)
	const signature = await signer.signMessage(ethers.utils.arrayify(hash))

	return new Response(JSON.stringify({
		sender,
		maxSize: maxSize.toString(),
		fee: fee.toString(),
		deadline: deadline.toString(),
		signature
	}))
}

function verifyTypedData(method: string, signature: string, deadline: number): string {
	if (now() > deadline) {
		return ''
	}

	const typedData = {
		primaryType: 'Request',
		types: {
			EIP712Domain: [
				{ name: 'name', type: 'string' },
				{ name: 'version', type: 'string' },
				{ name: 'chainId', type: 'uint256' }
			],
			Request: [
				{ name: 'method', type: 'string' },
				{ name: 'deadline', type: 'uint256' }
			]
		},
		domain: {
			name: 'kaai.finance',
			version: '1',
			chainId: chainIdHex
		},
		message: {
			method,
			deadline
		}
	}

	const typedDataHash = ethers.utils._TypedDataEncoder.hashStruct(
		typedData.primaryType,
		{ Request: typedData.types.Request },
		typedData.message)
	const domainSeparator = ethers.utils._TypedDataEncoder.hashStruct(
		'EIP712Domain',
		{ EIP712Domain: typedData.types.EIP712Domain },
		typedData.domain)
	const rawData = ethers.utils.hexConcat(['0x1901', domainSeparator, typedDataHash])
	const challengeHash = ethers.utils.keccak256(rawData)

	return ethers.utils.recoverAddress(challengeHash, signature) || ''
}

async function upload(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
	const req = await request.formData()
	const id = req.get('id') as string
	const signature = req.get('signature') as string
	const deadline = +(req.get('deadline') as string)
	const file = req.get('file') as File
	const thumbnail = req.get('thumbnail') as File

	const address = verifyTypedData('upload', signature, deadline)
	if (!address) {
		return new Response('invalid signature', { status: 400 })
	}

	const encodeArgs = ethers.utils.defaultAbiCoder.encode(['uint256'], [id])
	const callData = ethers.utils.hexConcat(['0xf4c714b4', encodeArgs])
	const result = await ethCall(callData)

	const r = ethers.utils.defaultAbiCoder.decode(
		[
			'address sender',
			'uint256 maxSize',
			'uint256 uploadFee',
			'uint256 downloadFee',
			'bool active',
			'uint256 paidCount'
		],
		result
	) as FileResult

	if (r.sender.toLowerCase() !== address.toLowerCase()) {
		return new Response('not own', { status: 400 })
	}
	if (BigNumber.from(file.size).gt(r.maxSize)) {
		return new Response('file size exceed', { status: 400 })
	}
	if (thumbnail.size > thumbnailMaxSize) {
		return new Response('thumbnail size exceed', { status: 400 })
	}

	const obj = await env.BUCKET.head(`files/${id}`)
	if (obj) {
		return new Response('already upload', { status: 400 })
	}

	// upload file and thumbnail
	await Promise.all([
		env.BUCKET.put(`thumbnail/${id}`, thumbnail.stream(), {
			httpMetadata: {
				contentType: thumbnail.type
			}
		}),
		env.BUCKET.put(`files/${id}`, file.stream(), {
			httpMetadata: {
				contentType: file.type
			}
		})
	])

	return new Response('ok')
}

// download returns file if paid
async function download(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
	const url = new URL(request.url)
	const id = url.searchParams.get('id') || ''
	const signature = url.searchParams.get('signature') || ''
	const deadline = +(url.searchParams.get('deadline') || '0')

	const address = verifyTypedData('download', signature, deadline)
	if (!address) {
		return new Response('invalid signature', { status: 400 })
	}

	const encodeArgs = ethers.utils.defaultAbiCoder.encode(['uint256', 'address'], [id, address])
	const callData = ethers.utils.hexConcat(['0x50430957', encodeArgs])
	const result = await ethCall(callData)

	const r = ethers.utils.defaultAbiCoder.decode(['bool b'], result) as PaidResult
	if (!r.b) {
		return new Response('not paid', { status: 400 })
	}

	const file = await env.BUCKET.get(`files/${id}`)
	if (!file) {
		return new Response('not found', { status: 404 })
	}
	return new Response(file.body, {
		//@ts-ignore
		headers: {
			'content-type': file.httpMetadata.contentType,
			'cache-control': 'private, max-age=0'
		}
	})
}

async function thumbnail(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
	const url = new URL(request.url)
	const id = url.searchParams.get('id') || ''

	const cache = caches.default
	let response = await cache.match(request)
	if (response && response.ok) {
		return response
	}

	const file = await env.BUCKET.get(`thumbnail/${id}`)
	if (!file) {
		return new Response('not found', { status: 404 })
	}
	response = new Response(file.body, {
		//@ts-ignore
		headers: {
			'content-type': file.httpMetadata.contentType,
			'cache-control': 'public, max-age=31536000'
		}
	})
	ctx.waitUntil(cache.put(request, response.clone()))

	return response
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url)

		let resp = new Response('404', { status: 404 })
		if (request.method === 'OPTIONS') {
			resp = new Response(null, { status: 204 })
		} else if (request.method === 'POST' &&
			url.pathname === '/price') {
			resp = await price(request, env, ctx)
		} else if (request.method === 'POST' &&
			url.pathname === '/upload') {
			resp = await upload(request, env, ctx)
		} else if (['GET', 'HEAD'].includes(request.method) &&
			url.pathname === '/download') {
			return download(request, env, ctx)
		} else if (['GET', 'HEAD'].includes(request.method) &&
			url.pathname === '/thumbnail') {
			return thumbnail(request, env, ctx)
		}

		resp.headers.set('access-control-allow-origin', '*')
		resp.headers.set('access-control-allow-headers', 'content-type')
		resp.headers.set('access-control-expose-headers', 'content-type')
		resp.headers.set('x-content-type-options', 'nosniff')
		return resp
	}
}
