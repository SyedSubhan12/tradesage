import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/lib/authContext";
import { toast } from "sonner";
import { FaGoogle, FaApple, FaSignInAlt, FaEye, FaEyeSlash } from "react-icons/fa";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const { login, handleOAuthCallback } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const fragment = window.location.hash.substring(1);
    const params = new URLSearchParams(fragment);
    const accessToken = params.get("access_token");


    const handleOAuthLogin = async () => {
      if (accessToken) {
        setIsLoading(true);
        try {
          await handleOAuthCallback(accessToken);
          toast.success("Logged in successfully with Google");
          navigate("/dashboard");
        } catch (error) {
          console.error("OAuth callback error:", error);
          toast.error("Failed to log in with Google");
        } finally {
          setIsLoading(false);
        }
      }
    };

    handleOAuthLogin();
  }, [handleOAuthCallback, navigate]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const success = await login({ username: email, password });
      if (success) navigate("/dashboard");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-black text-white">
      <div className="flex-1 flex items-center justify-center p-8 relative z-10">
        <div className="w-full max-w-md bg-black/30 backdrop-blur-xl p-8 rounded-2xl border border-white/10 shadow-xl">
          <div className="space-y-6">
            <div className="space-y-2">
              <h1 className="text-3xl font-bold">Welcome back!</h1>
              <p className="text-gray-400">Enter your credentials to access your account</p>
            </div>

            <Button
              type="button"
              onClick={() => (window.location.href = "/oauth/login/google")}
              variant="outline"
              className="w-full bg-white/5 border-white/20 hover:bg-white/10 hover:border-white/30 text-white"
              disabled={isLoading}
            >
              <FaGoogle className="w-4 h-4 mr-2" />
              Continue with Google
            </Button>

            <div className="relative my-6">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t border-white/10" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-black px-2 text-gray-400">Or continue with</span>
              </div>
            </div>

            <form onSubmit={handleLogin} className="space-y-6">
              <div className="space-y-2">
                <label htmlFor="email" className="text-sm font-medium text-gray-300">Email address</label>
                <Input
                  id="email"
                  type="email"
                  placeholder="Enter your email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  disabled={isLoading}
                  className="bg-white/10 border-white/20 text-white placeholder:text-gray-500"
                />
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label htmlFor="password" className="text-sm font-medium text-gray-300">Password</label>
                  <Link to="/auth/forgot-password" className="text-sm text-plasma-purple hover:text-plasma-purple/80">
                    Forgot password?
                  </Link>
                </div>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    disabled={isLoading}
                    className="pr-10 bg-white/10 border-white/20 text-white placeholder:text-gray-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-500 hover:text-white"
                    tabIndex={-1}
                  >
                    {showPassword ? <FaEyeSlash /> : <FaEye />}
                  </button>
                </div>
              </div>

              <div className="flex items-center space-x-2">
                <Checkbox
                  id="remember"
                  checked={rememberMe}
                  onCheckedChange={(checked) => setRememberMe(Boolean(checked))}
                  disabled={isLoading}
                  className="border-white/20 data-[state=checked]:bg-plasma-purple data-[state=checked]:border-plasma-purple"
                />
                <label htmlFor="remember" className="text-sm font-medium text-gray-300">
                  Remember for 30 days
                </label>
              </div>

              <Button
                type="submit"
                disabled={isLoading}
                className="w-full bg-plasma-purple hover:bg-plasma-purple/90 text-white font-medium flex items-center justify-center gap-2"
              >
                {isLoading ? (
                  <>
                    <svg className="animate-spin h-4 w-4 mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    Logging in...
                  </>
                ) : (
                  <>
                    <FaSignInAlt className="w-4 h-4 mr-2" />
                    Sign in
                  </>
                )}
              </Button>
            </form>

            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-white/10"></div>
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-black/30 text-gray-400">Or</span>
              </div>
            </div>

            <Button
              variant="outline"
              className="flex w-full items-center justify-center gap-2 bg-white/5 border-white/10 hover:bg-white/10 text-white"
              disabled
            >
              <FaApple className="w-4 h-4 mr-2" />
              <span>Sign in with Apple</span>
            </Button>

            <p className="text-sm text-gray-400 text-center mt-6">
              Don't have an account?{" "}
              <Link to="/auth/signup" className="text-plasma-purple hover:text-plasma-purple/80 font-medium">
                Sign Up
              </Link>
            </p>
          </div>
        </div>
      </div>

      <div className="hidden lg:block flex-1">
        <div className="h-full w-full relative">
          <img
            src="/33396f1e-01c2-4a30-8cae-c2b6ab4680e3.jpg.png"
            alt="Bitcoin cryptocurrency"
            className="h-full w-full object-cover"
          />
          <div className="absolute inset-0 bg-gradient-to-r from-black/80 to-transparent" />
        </div>
      </div>

      <div className="absolute top-0 left-0 w-full h-full overflow-hidden -z-10">
        <div className="absolute top-20 right-[20%] w-72 h-72 bg-plasma-purple/20 rounded-full blur-[80px]" />
        <div className="absolute bottom-20 left-[30%] w-72 h-72 bg-blue-500/20 rounded-full blur-[80px]" />
      </div>
    </div>
  );
};

export default Login;
