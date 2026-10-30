.PHONY: run test lint report clean

run:
	python3 python/pipeline.py

test:
	python3 -m unittest discover -s tests -v

lint:
	ruff check .

report: run
	Rscript -e "rmarkdown::render('r/analysis.Rmd')"

clean:
	rm -f data/events.csv data/absolutus.db r/analysis.html
