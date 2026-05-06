"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
} from "@/components/ui/sidebar"

const NAV = [
  { label: "dashboard", href: "/dashboard" },
  { label: "history",   href: "/history" },
  { label: "settings",  href: "/settings" },
]

export function AppSidebar() {
  const pathname = usePathname()

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="border-b border-sidebar-border px-4 py-3">
        <span className="font-mono text-micro uppercase text-sidebar-foreground group-data-[collapsible=icon]:hidden">
          hopper-recon
        </span>
        <span className="font-mono text-body text-sidebar-foreground/50 hidden group-data-[collapsible=icon]:block">h-r</span>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel className="font-mono text-micro text-sidebar-foreground/50 uppercase">
            {"// nav"}
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {NAV.map(({ label, href }) => (
                <SidebarMenuItem key={href}>
                  <SidebarMenuButton
                    asChild
                    isActive={pathname === href}
                    className="font-mono text-body rounded-none gap-2"
                  >
                    <Link href={href}>
                      <span className="text-muted shrink-0">&gt;_</span>
                      <span>{label}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="border-t border-sidebar-border px-4 py-2 group-data-[collapsible=icon]:hidden">
        <span className="font-mono text-micro text-sidebar-foreground/40">v0.1.0-alpha</span>
      </SidebarFooter>

      <SidebarRail />
    </Sidebar>
  )
}
