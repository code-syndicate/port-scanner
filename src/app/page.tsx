'use client'

import axios from 'axios'
import { SyntheticEvent, useState } from 'react'

export default function Home() {
  const [loading, setLoading] = useState(false)
  const [ipAddress, setIpAddress] = useState('')
  const [results, setResults] = useState<string | null>(null)
  const [scanType, setScanType] = useState<'ports' | 'vulnerabilities'>('ports')

  const handleScan = async (e: SyntheticEvent) => {
    e.preventDefault()

    setLoading(true)
    setResults(null)

    try {
      const response = await axios.post(
        '/api/scan',
        {
          ipAddress,
          scanType,
        },
        {
          headers: { 'Content-Type': 'application/json' },
        },
      )

      setResults(response.data.result || 'No results found')
    } catch (error) {
      setResults('Error occurred while scanning')
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="min-h-screen flex items-center justify-center bg-gray-100 p-6">
      <form
        onSubmit={handleScan}
        className="max-w-md w-full bg-white shadow-md rounded-lg p-6"
      >
        <h1 className="text-2xl font-bold mb-4">
          {`JohnAce's Vulnerability Scanner`}
        </h1>

        <div className="mb-4">
          <label
            className="block text-sm font-medium text-gray-700"
            htmlFor="ipAddress"
          >
            IP Address
          </label>

          <input
            required
            type="text"
            id="ipAddress"
            value={ipAddress}
            onChange={(e) => setIpAddress(e.target.value)}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
            placeholder="192.168.1.1"
          />
        </div>

        <div className="mb-4">
          <label
            className="block text-sm font-medium text-gray-700"
            htmlFor="scanType"
          >
            Scan Type
          </label>

          <select
            id="scanType"
            value={scanType}
            onChange={(e) =>
              setScanType(e.target.value as 'ports' | 'vulnerabilities')
            }
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
          >
            <option value="ports">Port Scan</option>
            <option value="vulnerabilities">Vulnerability Scan</option>
          </select>
        </div>

        <button
          disabled={loading}
          className="w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:bg-indigo-300 disabled:hover:cursor-wait"
        >
          {loading ? 'Scanning...' : 'Start Scan'}
        </button>

        {results && (
          <div className="mt-6 p-4 bg-gray-50 border border-gray-200 rounded-md shadow-sm">
            <h2 className="text-lg font-medium text-gray-900">Results</h2>
            <pre className="mt-2 text-sm text-gray-600 whitespace-pre-wrap">
              {results}
            </pre>
          </div>
        )}
      </form>
    </main>
  )
}
