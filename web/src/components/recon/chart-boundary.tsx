"use client"

import * as React from "react"

interface State { error: Error | null }

export class ChartBoundary extends React.Component<
  { children: React.ReactNode; label?: string },
  State
> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error) {
    if (process.env.NODE_ENV !== "production") {
      console.warn(`[chart-boundary${this.props.label ? `:${this.props.label}` : ""}]`, error)
    }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex items-center justify-center h-32 px-2 text-body text-muted-foreground-3 border border-destructive bg-card">
          <span className="font-mono">[CHART_ERR] {this.state.error.message.slice(0, 60)}</span>
        </div>
      )
    }
    return this.props.children
  }
}
