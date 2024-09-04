import { promisify } from 'util'
import { exec } from 'child_process'
import { NextResponse } from 'next/server'

const execAsync = promisify(exec)

export async function POST(request: Request) {
  try {
    const { ipAddress, scanType } = await request.json()

    if (!ipAddress || !scanType) {
      return NextResponse.json(
        { result: 'IP address and scan type are required' },
        { status: 400 },
      )
    }

    const validScanTypes = ['ports', 'vulnerabilities']

    if (!validScanTypes.includes(scanType)) {
      return NextResponse.json(
        { result: 'Invalid scan type. Use "ports" or "vulnerabilities".' },

        { status: 400 },
      )
    }

    const { stdout, stderr } = await execAsync(
      `python3 utils/scanner.py ${ipAddress} ${scanType}`,
    )

    if (stderr) {
      console.error(`Python error: ${stderr}`)

      return NextResponse.json(
        { result: 'Error executing the scan.' },
        { status: 500 },
      )
    }

    const results = stdout.trim().split('\n').filter(Boolean)

    return NextResponse.json({ result: results.join('\n') }, { status: 200 })
  } catch (error) {
    console.error(`Error executing scan: ${error}`)

    return NextResponse.json(
      { result: 'Error executing the scan.' },

      { status: 500 },
    )
  }
}
