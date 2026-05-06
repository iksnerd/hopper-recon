import { CopyableText } from "./copyable-text"

export function CopyableTextDemo() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="mb-3 text-sm font-semibold">Default variant</h2>
        <CopyableText text="example.com" />
      </div>

      <div>
        <h2 className="mb-3 text-sm font-semibold">With label</h2>
        <CopyableText
          text="api.example.com"
          label="Subdomain"
        />
      </div>

      <div>
        <h2 className="mb-3 text-sm font-semibold">Code variant</h2>
        <CopyableText
          text="192.168.1.1"
          label="IP Address"
          variant="code"
        />
      </div>

      <div>
        <h2 className="mb-3 text-sm font-semibold">Long content (scrollable)</h2>
        <CopyableText
          text="ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIFPILzuR2FW1vH3FLpwA8rn9Yar9m3bBKnAKRHfBL5c9kBFP8i6nVKGZ0rCvCfGgNYO1vxdqM0WNq9jEp4A6W8="
          label="SSH Key"
          variant="code"
        />
      </div>
    </div>
  )
}