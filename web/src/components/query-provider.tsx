"use client"

import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { ReactQueryDevtools } from "@tanstack/react-query-devtools"
import * as React from "react"
import { usePathname } from "next/navigation"

export function QueryProvider({ children }: { children: React.ReactNode }) {
  const [client] = React.useState(
    () => new QueryClient({ defaultOptions: { queries: { staleTime: 30_000, refetchOnWindowFocus: false } } })
  )
  // The printable report (/report/*) is meant for "Save as PDF": a devtools
  // button on it would be printed into the document.
  const pathname = usePathname()
  const showDevtools = !pathname?.startsWith("/report/")
  return (
    <QueryClientProvider client={client}>
      {children}
      {showDevtools && <ReactQueryDevtools initialIsOpen={false} />}
    </QueryClientProvider>
  )
}
