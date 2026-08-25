# Multi-stage Dockerfile for ShadowLure (.NET 9 Minimal API)
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /app

# Copy csproj files and restore dependencies
COPY ShadowLure.sln .
COPY src/ShadowLure.Core/*.csproj ./src/ShadowLure.Core/
COPY src/ShadowLure.Shadow/*.csproj ./src/ShadowLure.Shadow/
COPY src/ShadowLure.Profiling/*.csproj ./src/ShadowLure.Profiling/
COPY src/ShadowLure.Infrastructure/*.csproj ./src/ShadowLure.Infrastructure/
COPY src/ShadowLure.Api/*.csproj ./src/ShadowLure.Api/

RUN dotnet restore

# Copy source and publish
COPY . .
WORKDIR /app/src/ShadowLure.Api
RUN dotnet publish -c Release -o /app/out

# Runtime image
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app
COPY --from=build /app/out .

EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
ENTRYPOINT ["dotnet", "ShadowLure.Api.dll"]
