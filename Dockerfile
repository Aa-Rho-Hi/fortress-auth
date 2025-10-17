
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ./src/FortressAuth.Api/FortressAuth.Api.csproj ./src/FortressAuth.Api/
RUN dotnet restore ./src/FortressAuth.Api/FortressAuth.Api.csproj
COPY . .
RUN dotnet publish ./src/FortressAuth.Api/FortressAuth.Api.csproj -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "FortressAuth.Api.dll"]
