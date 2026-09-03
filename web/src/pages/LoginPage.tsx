import { FormEvent, useState } from "react";
import { Loader2, Lock, User } from "lucide-react";
import { BrandMark } from "@/components/BrandMark";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PRODUCT_NAME } from "@/brand";
import { login } from "@/lib/auth";

interface LoginPageProps {
  onSuccess: (username: string) => void;
}

export default function LoginPage({ onSuccess }: LoginPageProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (loading) return;
    setError(null);
    if (!username.trim() || !password) {
      setError("请输入用户名和密码");
      return;
    }
    setLoading(true);
    try {
      const result = await login(username.trim(), password);
      onSuccess(result.username);
    } catch (err) {
      setError(err instanceof Error ? err.message : "登录失败，请稍后重试");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-dvh items-center justify-center bg-slate-900 px-4">
      {/* 背景装饰 */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 overflow-hidden"
      >
        <div className="absolute -top-40 left-1/2 h-96 w-[42rem] -translate-x-1/2 rounded-full bg-indigo-500/10 blur-3xl" />
        <div className="absolute bottom-0 right-0 h-72 w-96 rounded-full bg-cyan-500/10 blur-3xl" />
      </div>

      <div className="relative w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3">
          <BrandMark alt={PRODUCT_NAME} className="h-14 w-14" />
          <h1 className="text-2xl font-semibold tracking-tight text-slate-100">
            {PRODUCT_NAME}
          </h1>
          <p className="text-sm text-slate-400">
            请登录后使用 AI 工作流平台
          </p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="space-y-4 rounded-xl border border-slate-700/50 bg-slate-800/60 p-6 shadow-xl backdrop-blur"
        >
          <div className="space-y-1.5">
            <Label htmlFor="auth-username" className="text-slate-300">
              用户名
            </Label>
            <div className="relative">
              <User
                size={16}
                className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
                aria-hidden="true"
              />
              <Input
                id="auth-username"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="请输入用户名"
                className="pl-9 bg-slate-900/60 border-slate-700 text-slate-100 placeholder:text-slate-500"
                disabled={loading}
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="auth-password" className="text-slate-300">
              密码
            </Label>
            <div className="relative">
              <Lock
                size={16}
                className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
                aria-hidden="true"
              />
              <Input
                id="auth-password"
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="请输入密码"
                className="pl-9 pr-10 bg-slate-900/60 border-slate-700 text-slate-100 placeholder:text-slate-500"
                disabled={loading}
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded px-1.5 py-1 text-xs text-slate-400 hover:text-slate-200"
                tabIndex={-1}
              >
                {showPassword ? "隐藏" : "显示"}
              </button>
            </div>
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300"
            >
              {error}
            </div>
          )}

          <Button
            type="submit"
            className="w-full bg-indigo-500 hover:bg-indigo-600 text-white"
            disabled={loading}
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                登录中...
              </>
            ) : (
              "登 录"
            )}
          </Button>
        </form>

        <p className="mt-6 text-center text-xs text-slate-500">
          需要管理员为你配置账号并授权后方可访问
        </p>
      </div>
    </div>
  );
}
