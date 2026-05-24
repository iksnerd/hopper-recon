"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { useTheme } from "next-themes"
import pkg from "../../package.json"
import { Radar, History, SlidersHorizontal, Info, Sun, Moon, type LucideIcon } from "lucide-react"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"

const NAV: { label: string; href: string; icon: LucideIcon }[] = [
  { label: "dashboard", href: "/dashboard", icon: Radar },
  { label: "history",   href: "/history",   icon: History },
  { label: "settings",  href: "/settings",  icon: SlidersHorizontal },
  { label: "about",     href: "/about",     icon: Info },
]

export function AppSidebar() {
  const pathname = usePathname()
  const { resolvedTheme, setTheme } = useTheme()

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="px-4 py-3">
        <div className="flex items-center gap-2 group-data-[collapsible=icon]:hidden">
          <span className="size-2 bg-terminal-green shrink-0" aria-hidden />
          <span className="font-mono text-body uppercase tracking-widest font-bold text-foreground">
            hopper-recon
          </span>
        </div>
        <span className="font-mono text-body text-terminal-green hidden group-data-[collapsible=icon]:block text-center">▮</span>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {NAV.map(({ label, href, icon: Icon }) => {
                const active = pathname === href || pathname.startsWith(`${href}/`)
                return (
                  <SidebarMenuItem key={href}>
                    <SidebarMenuButton
                      asChild
                      isActive={active}
                      className="font-mono text-body rounded-none gap-2.5 uppercase tracking-wide text-muted-foreground-2 hover:text-foreground hover:bg-card-hover data-[active=true]:text-terminal-green data-[active=true]:bg-card-hover data-[active=true]:font-bold relative data-[active=true]:before:absolute data-[active=true]:before:left-0 data-[active=true]:before:top-1.5 data-[active=true]:before:bottom-1.5 data-[active=true]:before:w-[2px] data-[active=true]:before:bg-terminal-green"
                    >
                      <Link href={href}>
                        <Icon
                          className={`shrink-0 size-4 ${active ? "text-terminal-green" : "text-muted-foreground-2"}`}
                          strokeWidth={active ? 2.25 : 1.75}
                          aria-hidden
                        />
                        <span className="group-data-[collapsible=icon]:hidden">{label}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                )
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="px-4 py-2 group-data-[collapsible=icon]:hidden">
        <div className="flex items-center justify-between">
          <span className="font-mono text-micro tracking-widest uppercase text-muted-foreground-3">v{pkg.version}</span>
          <button
            onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
            className="text-muted-foreground-3 hover:text-terminal-green transition-colors"
            aria-label="Toggle theme"
          >
            {resolvedTheme === "dark" ? <Sun className="size-3.5" /> : <Moon className="size-3.5" />}
          </button>
        </div>
      </SidebarFooter>

    </Sidebar>
  )
}
