# Maki Blog

## Testing

To test dev version, run the following command into this folder : 

```bash
sudo docker run --rm -it -v $PWD:/src -p 1313:1313 -u hugo jguyomard/hugo-builder hugo server -w --bind=0.0.0.0
```

## Description


Website sources from: https://acknak.fr/ 

Customized version based on:

- GoHugo
- Hyde-Hyde's theme
- A fork from Laluka (https://github.com/ThinkLoveShare/sources)
- Some customization from Haax (https://github.com/Haaxmax/haaxmax.github.io)

I'm sharing the sources used to generate the Website, since it took me some times to adjust to my needs.
