.PHONY: run report clean

run:
	python3 python/pipeline.py

report: run
	Rscript -e "rmarkdown::render('r/analysis.Rmd')"

clean:
	rm -f data/events.csv data/absolutus.db r/analysis.html
