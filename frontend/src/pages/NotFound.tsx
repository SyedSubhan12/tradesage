import { useLocation, useNavigate } from "react-router-dom";
import { useEffect } from "react";
import { NotFoundPage } from "@/components/ui/404-page-not-found";

export default function NotFound() {
  const location = useLocation();
  const navigate = useNavigate();

  // Log attempted path – helpful for debugging broken links.
  useEffect(() => {
    console.error("404 Error: attempted path:", location.pathname);
  }, [location.pathname]);

  // Reuse the shared UI component and pass router navigate if ever needed.
  return <NotFoundPage key="not-found" />;
}
