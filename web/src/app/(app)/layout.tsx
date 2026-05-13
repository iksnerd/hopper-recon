import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"
import { TooltipProvider } from "@/components/ui/tooltip"
import { AppSidebar } from "@/components/app-sidebar"
import { OperatorWarningBanner } from "@/components/recon/operator-warning-banner"

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <TooltipProvider delayDuration={200}>
    <SidebarProvider>
      <AppSidebar />
      {/* min-w-0 lets the main column shrink below intrinsic content width
          (long tables, recharts SVGs, JARM hashes). Without it a flex child
          defaults to min-content and the page can push past the viewport
          on the right. */}
      <SidebarInset className="bg-background grid-bg min-w-0">
        <OperatorWarningBanner />
        {children}
      </SidebarInset>
    </SidebarProvider>
    </TooltipProvider>
  )
}
