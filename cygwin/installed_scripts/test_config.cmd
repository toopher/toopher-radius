if exist etc\raddb\toopher_radius_config.pm (
  exit /B 0
) else (
  msg %SESSIONNAME% "Toopher-RADIUS configuration is missing!  Please run Toopher RADIUS Configuration first"
  exit /B 1
)