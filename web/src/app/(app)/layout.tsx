import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"
import { AppSidebar } from "@/components/app-sidebar"

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <SidebarProvider>
      <AppSidebar />
      {/* min-w-0 lets the main column shrink below intrinsic content width
          (long tables, recharts SVGs, JARM hashes). Without it a flex child
          defaults to min-content and the page can push past the viewport
          on the right. */}
      <SidebarInset className="bg-background grid-bg min-w-0">
        {children}
      </SidebarInset>
    </SidebarProvider>
  )
}
