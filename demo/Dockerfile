# escape=`
FROM microsoft/dotnet-framework:4.7.2-sdk AS build-env
COPY Integration.sln .
COPY ./MiraclAuthentication ./MiraclAuthentication
COPY ./demo ./demo
RUN nuget restore -Verbosity quiet
WORKDIR /demo
RUN msbuild /m /verbosity:minimal /p:Configuration=Release

FROM microsoft/aspnet:4.7.2 AS runtime
RUN New-Item -Path 'C:\demo' -Type Directory; `
    New-Website -Name 'demo' -PhysicalPath 'C:\demo' -Port 8000 -Force
EXPOSE 8000
COPY --from=build-env /demo/. /demo
