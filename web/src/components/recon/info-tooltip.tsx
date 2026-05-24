"use client"

import { Info } from "lucide-react"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"

export function InfoTooltip({ text }: { text: string }) {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          className="inline-flex items-center cursor-pointer text-muted-foreground-3 hover:text-muted-foreground transition-colors ml-1 align-middle"
          aria-label="more info"
        >
          <Info className="size-3" />
        </button>
      </PopoverTrigger>
      <PopoverContent
        side="top"
        className="max-w-[260px] text-xs leading-relaxed rounded-none p-3 font-mono"
      >
        {text}
      </PopoverContent>
    </Popover>
  )
}
