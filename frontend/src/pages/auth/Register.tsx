import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/lib/authContext";
import { UserRole } from "@/lib/authContext";
import { toast } from "sonner";
import { FaEye, FaEyeSlash, FaGoogle, FaApple } from "react-icons/fa";

const Register = () => {
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
    confirmPassword: "",
    firstName: "",
    lastName: "",
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  
  const { register, handleOAuthCallback } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const fragment = window.location.hash.substring(1);
    const params = new URLSearchParams(fragment);
    const accessToken = params.get("access_token");
    const refreshToken = params.get("refresh_token");

    const handleOAuthRegister = async () => {
      if (accessToken && refreshToken) {
        setIsLoading(true);
        try {
          await handleOAuthCallback(accessToken, refreshToken);
          toast.success("Account created successfully with Google");
          navigate("/dashboard");
        } catch (error) {
          console.error("OAuth callback error:", error);
          toast.error("Failed to create account with Google");
        } finally {
          setIsLoading(false);
        }
      }
    };

    handleOAuthRegister();
  }, [handleOAuthCallback, navigate]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    
    // Basic validation
    if (formData.password !== formData.confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    
    if (formData.password.length < 8) {
      setError("Password must be at least 8 characters long");
      return;
    }
    
    setIsLoading(true);
    
    try {
      const userData = {
        username: formData.username,
        email: formData.email,
        password: formData.password,
        first_name: formData.firstName,
        last_name: formData.lastName,
        role: UserRole.TRADER, // Default role
      };
      
      const success = await register(userData);
      
      if (success) {
        // Redirect to dashboard after successful registration
        navigate('/dashboard');
      }
    } catch (err: any) {
      console.error('Registration error:', err);
      setError(
        err.message || 'Registration failed. Please try again.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-black text-white">
      {/* Left side - Registration Form */}
      <div className="flex-1 flex items-center justify-center p-8 relative z-10">
        <div className="w-full max-w-md bg-black/30 backdrop-blur-xl p-8 rounded-2xl border border-white/10 shadow-xl">
          <div className="space-y-6">
            <div className="space-y-2 text-center">
              <h1 className="text-3xl font-bold text-white">Create an account</h1>
              <p className="text-gray-400">
                Enter your details to get started
              </p>
            </div>

            {/* Social Login Buttons */}
            <div className="space-y-4">
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
                  <span className="w-full border-t border-white/10"></span>
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-black px-2 text-gray-400">Or continue with email</span>
                </div>
              </div>
            </div>

            {error && (
              <div className="p-3 bg-red-500/20 border border-red-500/50 text-red-200 text-sm rounded-lg">
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label htmlFor="firstName" className="text-sm font-medium text-gray-300">
                    First Name
                  </label>
                  <Input
                    id="firstName"
                    name="firstName"
                    type="text"
                    placeholder="John"
                    value={formData.firstName}
                    onChange={handleChange}
                    required
                    className="w-full bg-white/10 border-white/20 focus:border-plasma-purple text-white placeholder:text-gray-500"
                    disabled={isLoading}
                  />
                </div>
                <div className="space-y-2">
                  <label htmlFor="lastName" className="text-sm font-medium text-gray-300">
                    Last Name
                  </label>
                  <Input
                    id="lastName"
                    name="lastName"
                    type="text"
                    placeholder="Doe"
                    value={formData.lastName}
                    onChange={handleChange}
                    required
                    className="w-full bg-white/10 border-white/20 focus:border-plasma-purple text-white placeholder:text-gray-500"
                    disabled={isLoading}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <label htmlFor="username" className="text-sm font-medium text-gray-300">
                  Username
                </label>
                <Input
                  id="username"
                  name="username"
                  type="text"
                  placeholder="johndoe"
                  value={formData.username}
                  onChange={handleChange}
                  required
                  className="w-full bg-white/10 border-white/20 focus:border-plasma-purple text-white placeholder:text-gray-500"
                  disabled={isLoading}
                />
              </div>

              <div className="space-y-2">
                <label htmlFor="email" className="text-sm font-medium text-gray-300">
                  Email address
                </label>
                <Input
                  id="email"
                  name="email"
                  type="email"
                  placeholder="john@example.com"
                  value={formData.email}
                  onChange={handleChange}
                  required
                  className="w-full bg-white/10 border-white/20 focus:border-plasma-purple text-white placeholder:text-gray-500"
                  disabled={isLoading}
                />
              </div>

              <div className="space-y-2">
                <label htmlFor="password" className="text-sm font-medium text-gray-300">
                  Password
                </label>
                <div className="relative">
                  <Input
                    id="password"
                    name="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="••••••••"
                    value={formData.password}
                    onChange={handleChange}
                    required
                    className="w-full pr-10 bg-white/10 border-white/20 focus:border-plasma-purple text-white placeholder:text-gray-500"
                    disabled={isLoading}
                  />
                  <button 
                    type="button" 
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <FaEyeSlash /> : <FaEye />}
                  </button>
                </div>
                <p className="text-xs text-gray-400">
                  Must be at least 8 characters
                </p>
              </div>

              <div className="space-y-2">
                <label htmlFor="confirmPassword" className="text-sm font-medium text-gray-300">
                  Confirm Password
                </label>
                <div className="relative">
                  <Input
                    id="confirmPassword"
                    name="confirmPassword"
                    type={showConfirmPassword ? "text" : "password"}
                    placeholder="••••••••"
                    value={formData.confirmPassword}
                    onChange={handleChange}
                    required
                    className="w-full pr-10 bg-white/10 border-white/20 focus:border-plasma-purple text-white placeholder:text-gray-500"
                    disabled={isLoading}
                  />
                  <button 
                    type="button" 
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  >
                    {showConfirmPassword ? <FaEyeSlash /> : <FaEye />}
                  </button>
                </div>
              </div>

              <Button 
                type="submit" 
                className="w-full bg-plasma-purple hover:bg-plasma-purple/90 text-white font-medium mt-6"
                disabled={isLoading}
              >
                {isLoading ? "Creating account..." : "Create Account"}
              </Button>
            </form>

            {/* Apple Login Button */}
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
              className="w-full flex items-center justify-center gap-2 bg-white/5 border-white/10 hover:bg-white/10 text-white"
              disabled
            >
              <FaApple className="w-4 h-4" />
              <span>Sign up with Apple</span>
            </Button>

            <div className="text-center mt-6">
              <p className="text-sm text-gray-400">
                Already have an account?{" "}
                <Link
                  to="/auth/login"
                  className="text-plasma-purple hover:text-plasma-purple/80 font-medium"
                >
                  Sign In
                </Link>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Right side - Image (same as login) */}
      <div className="hidden lg:block flex-1">
        <div className="h-full w-full relative">
          <img
            src="/33396f1e-01c2-4a30-8cae-c2b6ab4680e3.jpg.png"
            alt="Bitcoin cryptocurrency"
            className="h-full w-full object-cover"
          />
          <div className="absolute inset-0 bg-gradient-to-r from-black/80 to-transparent"></div>
        </div>
      </div>

      {/* Background effects */}
      <div className="absolute top-0 left-0 w-full h-full overflow-hidden -z-10">
        <div className="absolute top-20 right-[20%] w-72 h-72 bg-plasma-purple/20 rounded-full filter blur-[80px]"></div>
        <div className="absolute bottom-20 left-[30%] w-72 h-72 bg-blue-500/20 rounded-full filter blur-[80px]"></div>
      </div>
    </div>
  );
};

export default Register;