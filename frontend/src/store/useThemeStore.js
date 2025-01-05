import { create } from "zustand";

export const useThemeStore = create((set) => ({
    theme: localStorage.getItem("chatty-theme") || "light",
    setTheme: (theme) => {
        localStorage.setItem("chatty-theme", theme)
        set({ theme })
    }
}))